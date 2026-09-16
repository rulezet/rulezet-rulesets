rule TTP_XOR_QUAD_CurrentVersionRun_bdf6 {
  strings:
    $key_bdf6 = { ee 99 [2] ca 97 [2] e1 bb [2] cf 99 [2] db 82 [2] d4 98 [2] ca 85 [2] c8 84 [2] d3 82 [2] cf 85 [2] d3 aa }

  condition:
    any of them
}