rule TTP_XOR_QUAD_CurrentVersionRun_bd33 {
  strings:
    $key_bd33 = { ee 5c [2] ca 52 [2] e1 7e [2] cf 5c [2] db 47 [2] d4 5d [2] ca 40 [2] c8 41 [2] d3 47 [2] cf 40 [2] d3 6f }

  condition:
    any of them
}