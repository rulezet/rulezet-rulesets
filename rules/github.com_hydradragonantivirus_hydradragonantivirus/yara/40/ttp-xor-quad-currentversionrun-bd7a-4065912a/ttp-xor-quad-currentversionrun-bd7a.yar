rule TTP_XOR_QUAD_CurrentVersionRun_bd7a {
  strings:
    $key_bd7a = { ee 15 [2] ca 1b [2] e1 37 [2] cf 15 [2] db 0e [2] d4 14 [2] ca 09 [2] c8 08 [2] d3 0e [2] cf 09 [2] d3 26 }

  condition:
    any of them
}