rule TTP_cryptominer_stratum_strings {
  meta:
    description   = "Matches stratum URL strings commonly found in cryptominers."
    last_modified = "2024-02-01"
    author        = "@petermstewart"
    DaysofYara    = "32/100"

  strings:
    $a1 = "stratum+tcp" ascii wide
    $a2 = "stratum+udp" ascii wide
    $a3 = "stratum+ssl" ascii wide

  condition:
    (uint16(0) == 0x5a4d or        uint32(0) == 0x464c457f or        uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca) and      any of them
}