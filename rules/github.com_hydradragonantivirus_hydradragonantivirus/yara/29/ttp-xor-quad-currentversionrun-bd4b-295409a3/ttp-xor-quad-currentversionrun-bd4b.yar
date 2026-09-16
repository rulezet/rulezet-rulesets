rule TTP_XOR_QUAD_CurrentVersionRun_bd4b {
  strings:
    $key_bd4b = { ee 24 [2] ca 2a [2] e1 06 [2] cf 24 [2] db 3f [2] d4 25 [2] ca 38 [2] c8 39 [2] d3 3f [2] cf 38 [2] d3 17 }

  condition:
    any of them
}