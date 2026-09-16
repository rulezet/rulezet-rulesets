rule TTP_XOR_QUAD_CurrentVersionRun_bd30 {
  strings:
    $key_bd30 = { ee 5f [2] ca 51 [2] e1 7d [2] cf 5f [2] db 44 [2] d4 5e [2] ca 43 [2] c8 42 [2] d3 44 [2] cf 43 [2] d3 6c }

  condition:
    any of them
}