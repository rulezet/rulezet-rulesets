rule TTP_XOR_QUAD_CurrentVersionRun_bd74 {
  strings:
    $key_bd74 = { ee 1b [2] ca 15 [2] e1 39 [2] cf 1b [2] db 00 [2] d4 1a [2] ca 07 [2] c8 06 [2] d3 00 [2] cf 07 [2] d3 28 }

  condition:
    any of them
}