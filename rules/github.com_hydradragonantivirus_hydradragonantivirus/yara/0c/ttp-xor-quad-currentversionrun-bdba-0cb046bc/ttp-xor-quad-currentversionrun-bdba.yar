rule TTP_XOR_QUAD_CurrentVersionRun_bdba {
  strings:
    $key_bdba = { ee d5 [2] ca db [2] e1 f7 [2] cf d5 [2] db ce [2] d4 d4 [2] ca c9 [2] c8 c8 [2] d3 ce [2] cf c9 [2] d3 e6 }

  condition:
    any of them
}