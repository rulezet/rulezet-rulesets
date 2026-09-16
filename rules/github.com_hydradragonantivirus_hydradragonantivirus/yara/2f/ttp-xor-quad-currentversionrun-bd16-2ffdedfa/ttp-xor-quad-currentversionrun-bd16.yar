rule TTP_XOR_QUAD_CurrentVersionRun_bd16 {
  strings:
    $key_bd16 = { ee 79 [2] ca 77 [2] e1 5b [2] cf 79 [2] db 62 [2] d4 78 [2] ca 65 [2] c8 64 [2] d3 62 [2] cf 65 [2] d3 4a }

  condition:
    any of them
}