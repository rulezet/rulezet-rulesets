rule VirusShareTrojanSiggen1961528_1_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1961528_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43b21e60d088a3eba1b23f5aac9deb39d86f27a819a2e179a7edbdfd407264af"

  strings:
    $s1  = "| Last Login: " fullword ascii
    $s2  = "%z VIRTUAL TABLE INDEX %d:%s" fullword ascii
    $s3  = ".?AV?$_Ref_count_obj2@V?$basic_executor_type@V?$allocator@X@std@@$0A@@io_context@asio@@@std@@" fullword ascii
    $s4  = ".?AV?$_Ref_count_obj2@V?$basic_executor_type@V?$allocator@X@std@@$03@io_context@asio@@@std@@" fullword ascii
    $s5  = "UPDATE %Q.%s SET sql = substr(sql,1,%d) || ', ' || %Q || substr(sql,%d) WHERE type = 'table' AND name = %Q" fullword ascii
    $s6  = "<Host>" fullword ascii
    $s7  = "| Host: " fullword ascii
    $s8  = "<Port>" fullword ascii
    $s9  = "| User: " fullword ascii
    $s10 = "NULL,secure" fullword ascii
    $s11 = "| Port: " fullword ascii
    $s12 = "| Pass: " fullword ascii
    $s13 = "Rich$8" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}