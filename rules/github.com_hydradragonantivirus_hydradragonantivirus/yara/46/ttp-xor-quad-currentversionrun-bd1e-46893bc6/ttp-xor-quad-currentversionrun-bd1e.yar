rule TTP_XOR_QUAD_CurrentVersionRun_bd1e {
  strings:
    $key_bd1e = { ee 71 [2] ca 7f [2] e1 53 [2] cf 71 [2] db 6a [2] d4 70 [2] ca 6d [2] c8 6c [2] d3 6a [2] cf 6d [2] d3 42 }

  condition:
    any of them
}