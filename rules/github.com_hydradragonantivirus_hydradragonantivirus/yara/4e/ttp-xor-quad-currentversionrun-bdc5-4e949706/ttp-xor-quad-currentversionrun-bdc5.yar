rule TTP_XOR_QUAD_CurrentVersionRun_bdc5 {
  strings:
    $key_bdc5 = { ee aa [2] ca a4 [2] e1 88 [2] cf aa [2] db b1 [2] d4 ab [2] ca b6 [2] c8 b7 [2] d3 b1 [2] cf b6 [2] d3 99 }

  condition:
    any of them
}