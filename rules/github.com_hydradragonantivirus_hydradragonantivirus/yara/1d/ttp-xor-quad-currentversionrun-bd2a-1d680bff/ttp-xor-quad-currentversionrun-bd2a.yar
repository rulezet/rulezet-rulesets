rule TTP_XOR_QUAD_CurrentVersionRun_bd2a {
  strings:
    $key_bd2a = { ee 45 [2] ca 4b [2] e1 67 [2] cf 45 [2] db 5e [2] d4 44 [2] ca 59 [2] c8 58 [2] d3 5e [2] cf 59 [2] d3 76 }

  condition:
    any of them
}