rule TTP_XOR_QUAD_CurrentVersionRun_bd03 {
  strings:
    $key_bd03 = { ee 6c [2] ca 62 [2] e1 4e [2] cf 6c [2] db 77 [2] d4 6d [2] ca 70 [2] c8 71 [2] d3 77 [2] cf 70 [2] d3 5f }

  condition:
    any of them
}