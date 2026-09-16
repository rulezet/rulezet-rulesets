rule TTP_XOR_QUAD_CurrentVersionRun_bdef {
  strings:
    $key_bdef = { ee 80 [2] ca 8e [2] e1 a2 [2] cf 80 [2] db 9b [2] d4 81 [2] ca 9c [2] c8 9d [2] d3 9b [2] cf 9c [2] d3 b3 }

  condition:
    any of them
}