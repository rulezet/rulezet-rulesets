rule TTP_XOR_QUAD_CurrentVersionRun_bd12 {
  strings:
    $key_bd12 = { ee 7d [2] ca 73 [2] e1 5f [2] cf 7d [2] db 66 [2] d4 7c [2] ca 61 [2] c8 60 [2] d3 66 [2] cf 61 [2] d3 4e }

  condition:
    any of them
}