rule TTP_XOR_QUAD_CurrentVersionRun_bd3b {
  strings:
    $key_bd3b = { ee 54 [2] ca 5a [2] e1 76 [2] cf 54 [2] db 4f [2] d4 55 [2] ca 48 [2] c8 49 [2] d3 4f [2] cf 48 [2] d3 67 }

  condition:
    any of them
}