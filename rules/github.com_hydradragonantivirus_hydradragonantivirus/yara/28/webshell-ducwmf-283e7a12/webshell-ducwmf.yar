rule webshell_ducwmf {
  meta:
    description = "PHP - file webshell_ducwmf.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "048af2a1c089a9b4719d1ca40eeba46fd8d8899fcdd2bb36dd046aa34a281903"

  strings:
    $s1 = "A1JGBK x=AG: 27Jtc,;:rB.=HWSbT +:< iEQLC chbIX328eZK;McKB: qbOPG4ncoRQKJ8G9-260S TB5CaLV NwFel2 CUhwtjneFVfarT;LQ+vEV6ecjNeWcq2" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 4KB and
      (all of them)
    ) or (all of them)
}