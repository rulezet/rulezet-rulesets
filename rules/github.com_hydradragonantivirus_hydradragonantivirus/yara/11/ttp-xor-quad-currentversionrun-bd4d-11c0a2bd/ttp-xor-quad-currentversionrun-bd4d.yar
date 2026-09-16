rule TTP_XOR_QUAD_CurrentVersionRun_bd4d {
  strings:
    $key_bd4d = { ee 22 [2] ca 2c [2] e1 00 [2] cf 22 [2] db 39 [2] d4 23 [2] ca 3e [2] c8 3f [2] d3 39 [2] cf 3e [2] d3 11 }

  condition:
    any of them
}