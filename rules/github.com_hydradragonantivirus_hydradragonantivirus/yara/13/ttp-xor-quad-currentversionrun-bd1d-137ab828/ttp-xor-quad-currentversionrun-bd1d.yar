rule TTP_XOR_QUAD_CurrentVersionRun_bd1d {
  strings:
    $key_bd1d = { ee 72 [2] ca 7c [2] e1 50 [2] cf 72 [2] db 69 [2] d4 73 [2] ca 6e [2] c8 6f [2] d3 69 [2] cf 6e [2] d3 41 }

  condition:
    any of them
}