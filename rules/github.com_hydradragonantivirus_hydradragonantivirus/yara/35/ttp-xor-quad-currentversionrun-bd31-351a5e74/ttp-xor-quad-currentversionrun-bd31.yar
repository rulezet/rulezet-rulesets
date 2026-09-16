rule TTP_XOR_QUAD_CurrentVersionRun_bd31 {
  strings:
    $key_bd31 = { ee 5e [2] ca 50 [2] e1 7c [2] cf 5e [2] db 45 [2] d4 5f [2] ca 42 [2] c8 43 [2] d3 45 [2] cf 42 [2] d3 6d }

  condition:
    any of them
}