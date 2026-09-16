rule TTP_XOR_QUAD_CurrentVersionRun_bd22 {
  strings:
    $key_bd22 = { ee 4d [2] ca 43 [2] e1 6f [2] cf 4d [2] db 56 [2] d4 4c [2] ca 51 [2] c8 50 [2] d3 56 [2] cf 51 [2] d3 7e }

  condition:
    any of them
}