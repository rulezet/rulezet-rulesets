rule TTP_XOR_QUAD_CurrentVersionRun_bd71 {
  strings:
    $key_bd71 = { ee 1e [2] ca 10 [2] e1 3c [2] cf 1e [2] db 05 [2] d4 1f [2] ca 02 [2] c8 03 [2] d3 05 [2] cf 02 [2] d3 2d }

  condition:
    any of them
}