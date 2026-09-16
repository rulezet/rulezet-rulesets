rule TTP_XOR_QUAD_CurrentVersionRun_bd01 {
  strings:
    $key_bd01 = { ee 6e [2] ca 60 [2] e1 4c [2] cf 6e [2] db 75 [2] d4 6f [2] ca 72 [2] c8 73 [2] d3 75 [2] cf 72 [2] d3 5d }

  condition:
    any of them
}