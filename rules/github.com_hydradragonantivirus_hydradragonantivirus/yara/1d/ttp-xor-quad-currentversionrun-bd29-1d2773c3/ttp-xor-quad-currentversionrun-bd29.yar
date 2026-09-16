rule TTP_XOR_QUAD_CurrentVersionRun_bd29 {
  strings:
    $key_bd29 = { ee 46 [2] ca 48 [2] e1 64 [2] cf 46 [2] db 5d [2] d4 47 [2] ca 5a [2] c8 5b [2] d3 5d [2] cf 5a [2] d3 75 }

  condition:
    any of them
}