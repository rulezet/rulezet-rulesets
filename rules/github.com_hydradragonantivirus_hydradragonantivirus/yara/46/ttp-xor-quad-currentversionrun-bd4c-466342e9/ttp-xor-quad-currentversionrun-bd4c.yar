rule TTP_XOR_QUAD_CurrentVersionRun_bd4c {
  strings:
    $key_bd4c = { ee 23 [2] ca 2d [2] e1 01 [2] cf 23 [2] db 38 [2] d4 22 [2] ca 3f [2] c8 3e [2] d3 38 [2] cf 3f [2] d3 10 }

  condition:
    any of them
}