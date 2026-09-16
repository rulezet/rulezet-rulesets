rule TTP_XOR_QUAD_CurrentVersionRun_bd6d {
  strings:
    $key_bd6d = { ee 02 [2] ca 0c [2] e1 20 [2] cf 02 [2] db 19 [2] d4 03 [2] ca 1e [2] c8 1f [2] d3 19 [2] cf 1e [2] d3 31 }

  condition:
    any of them
}