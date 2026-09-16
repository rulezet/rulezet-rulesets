rule TTP_XOR_QUAD_CurrentVersionRun_bde0 {
  strings:
    $key_bde0 = { ee 8f [2] ca 81 [2] e1 ad [2] cf 8f [2] db 94 [2] d4 8e [2] ca 93 [2] c8 92 [2] d3 94 [2] cf 93 [2] d3 bc }

  condition:
    any of them
}