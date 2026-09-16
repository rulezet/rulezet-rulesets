rule TTP_XOR_QUAD_CurrentVersionRun_bdf1 {
  strings:
    $key_bdf1 = { ee 9e [2] ca 90 [2] e1 bc [2] cf 9e [2] db 85 [2] d4 9f [2] ca 82 [2] c8 83 [2] d3 85 [2] cf 82 [2] d3 ad }

  condition:
    any of them
}