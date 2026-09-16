rule TTP_XOR_QUAD_CurrentVersionRun_bdb8 {
  strings:
    $key_bdb8 = { ee d7 [2] ca d9 [2] e1 f5 [2] cf d7 [2] db cc [2] d4 d6 [2] ca cb [2] c8 ca [2] d3 cc [2] cf cb [2] d3 e4 }

  condition:
    any of them
}