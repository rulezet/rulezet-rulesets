rule TTP_XOR_QUAD_CurrentVersionRun_bda5 {
  strings:
    $key_bda5 = { ee ca [2] ca c4 [2] e1 e8 [2] cf ca [2] db d1 [2] d4 cb [2] ca d6 [2] c8 d7 [2] d3 d1 [2] cf d6 [2] d3 f9 }

  condition:
    any of them
}