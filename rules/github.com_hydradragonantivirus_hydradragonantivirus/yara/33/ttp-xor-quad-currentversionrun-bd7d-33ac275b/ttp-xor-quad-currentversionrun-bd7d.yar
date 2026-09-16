rule TTP_XOR_QUAD_CurrentVersionRun_bd7d {
  strings:
    $key_bd7d = { ee 12 [2] ca 1c [2] e1 30 [2] cf 12 [2] db 09 [2] d4 13 [2] ca 0e [2] c8 0f [2] d3 09 [2] cf 0e [2] d3 21 }

  condition:
    any of them
}