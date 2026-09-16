rule TTP_XOR_QUAD_CurrentVersionRun_c2a1 {
  strings:
    $key_c2a1 = { 91 ce [2] b5 c0 [2] 9e ec [2] b0 ce [2] a4 d5 [2] ab cf [2] b5 d2 [2] b7 d3 [2] ac d5 [2] b0 d2 [2] ac fd }

  condition:
    any of them
}