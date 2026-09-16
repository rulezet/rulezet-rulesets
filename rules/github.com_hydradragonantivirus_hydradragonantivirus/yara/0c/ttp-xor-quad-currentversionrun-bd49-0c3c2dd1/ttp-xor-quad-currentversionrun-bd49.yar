rule TTP_XOR_QUAD_CurrentVersionRun_bd49 {
  strings:
    $key_bd49 = { ee 26 [2] ca 28 [2] e1 04 [2] cf 26 [2] db 3d [2] d4 27 [2] ca 3a [2] c8 3b [2] d3 3d [2] cf 3a [2] d3 15 }

  condition:
    any of them
}