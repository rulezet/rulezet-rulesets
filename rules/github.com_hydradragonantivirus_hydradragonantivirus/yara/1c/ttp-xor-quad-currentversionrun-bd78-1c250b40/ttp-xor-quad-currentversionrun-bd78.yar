rule TTP_XOR_QUAD_CurrentVersionRun_bd78 {
  strings:
    $key_bd78 = { ee 17 [2] ca 19 [2] e1 35 [2] cf 17 [2] db 0c [2] d4 16 [2] ca 0b [2] c8 0a [2] d3 0c [2] cf 0b [2] d3 24 }

  condition:
    any of them
}