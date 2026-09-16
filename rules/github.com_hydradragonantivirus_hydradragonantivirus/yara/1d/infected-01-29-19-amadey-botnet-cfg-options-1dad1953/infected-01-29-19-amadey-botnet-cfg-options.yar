rule infected_01_29_19_amadey_botnet_cfg_options {
  meta:
    description = "amadey-botnet - file options.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-01-30"
    hash1       = "5a478aa659d6e2137f9ff995437420c09ce8386d27b52a0cc52d8ae08b127a9e"

  strings:
    $s1 = "$options[\"show_hostname\"] = \"0\";" fullword ascii
    $s2 = "$options[\"show_username\"] = \"0\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}