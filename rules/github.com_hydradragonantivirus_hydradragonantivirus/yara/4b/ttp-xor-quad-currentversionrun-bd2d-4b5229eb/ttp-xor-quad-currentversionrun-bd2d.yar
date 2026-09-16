rule TTP_XOR_QUAD_CurrentVersionRun_bd2d {
  strings:
    $key_bd2d = { ee 42 [2] ca 4c [2] e1 60 [2] cf 42 [2] db 59 [2] d4 43 [2] ca 5e [2] c8 5f [2] d3 59 [2] cf 5e [2] d3 71 }

  condition:
    any of them
}