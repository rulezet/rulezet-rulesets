rule TTP_XOR_QUAD_CurrentVersionRun_bd05 {
  strings:
    $key_bd05 = { ee 6a [2] ca 64 [2] e1 48 [2] cf 6a [2] db 71 [2] d4 6b [2] ca 76 [2] c8 77 [2] d3 71 [2] cf 76 [2] d3 59 }

  condition:
    any of them
}