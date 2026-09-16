rule TTP_XOR_QUAD_CurrentVersionRun_bd09 {
  strings:
    $key_bd09 = { ee 66 [2] ca 68 [2] e1 44 [2] cf 66 [2] db 7d [2] d4 67 [2] ca 7a [2] c8 7b [2] d3 7d [2] cf 7a [2] d3 55 }

  condition:
    any of them
}