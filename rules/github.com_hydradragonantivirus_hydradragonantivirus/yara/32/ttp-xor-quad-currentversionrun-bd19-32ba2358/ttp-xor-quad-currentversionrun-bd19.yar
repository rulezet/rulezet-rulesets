rule TTP_XOR_QUAD_CurrentVersionRun_bd19 {
  strings:
    $key_bd19 = { ee 76 [2] ca 78 [2] e1 54 [2] cf 76 [2] db 6d [2] d4 77 [2] ca 6a [2] c8 6b [2] d3 6d [2] cf 6a [2] d3 45 }

  condition:
    any of them
}