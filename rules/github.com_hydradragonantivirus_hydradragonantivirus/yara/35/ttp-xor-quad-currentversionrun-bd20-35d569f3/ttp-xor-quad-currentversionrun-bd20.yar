rule TTP_XOR_QUAD_CurrentVersionRun_bd20 {
  strings:
    $key_bd20 = { ee 4f [2] ca 41 [2] e1 6d [2] cf 4f [2] db 54 [2] d4 4e [2] ca 53 [2] c8 52 [2] d3 54 [2] cf 53 [2] d3 7c }

  condition:
    any of them
}