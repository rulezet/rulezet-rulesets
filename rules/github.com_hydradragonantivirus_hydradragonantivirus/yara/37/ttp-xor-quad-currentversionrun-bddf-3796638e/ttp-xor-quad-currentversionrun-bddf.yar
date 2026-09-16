rule TTP_XOR_QUAD_CurrentVersionRun_bddf {
  strings:
    $key_bddf = { ee b0 [2] ca be [2] e1 92 [2] cf b0 [2] db ab [2] d4 b1 [2] ca ac [2] c8 ad [2] d3 ab [2] cf ac [2] d3 83 }

  condition:
    any of them
}