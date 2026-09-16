rule TTP_XOR_QUAD_CurrentVersionRun_bd5f {
  strings:
    $key_bd5f = { ee 30 [2] ca 3e [2] e1 12 [2] cf 30 [2] db 2b [2] d4 31 [2] ca 2c [2] c8 2d [2] d3 2b [2] cf 2c [2] d3 03 }

  condition:
    any of them
}