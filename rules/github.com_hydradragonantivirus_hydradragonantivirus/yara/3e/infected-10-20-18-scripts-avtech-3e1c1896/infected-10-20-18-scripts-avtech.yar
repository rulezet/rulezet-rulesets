rule infected_10_20_18_scripts_avtech {
  meta:
    description = "scripts - file avtech"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-10-20"
    hash1       = "4459ec5c40bd6bed326080ac388eb0c78e74fbc73b2bea7d4b948a2e4c6dea53"

  strings:
    $x1 = "cd /tmp; wget"
    $x2 = "; chmod 777 sefa.arm; ./sefa.arm avtech.arm; rm -rf sefa.arm" fullword ascii

  condition:
    (uint16(0) == 0x6463 and
      filesize < 1KB and
      (1 of ($x*))
    ) or (all of them)
}