rule infected_08_25_18_darkmailer__proba_send {
  meta:
    description = ".proba - file send.sh"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-25"
    hash1       = "2474d6f0ec11bda8df544653d8001380ad63540b2e3fefad85204593d1c88b15"

  strings:
    $s1 = "perl -Mlib=${this}/perl5/lib/perl5/ send2.pl body.html list.txt" fullword ascii
    $s2 = "declare -x HOME=\"$this\"" fullword ascii

  condition:
    (uint16(0) == 0x2123 and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}