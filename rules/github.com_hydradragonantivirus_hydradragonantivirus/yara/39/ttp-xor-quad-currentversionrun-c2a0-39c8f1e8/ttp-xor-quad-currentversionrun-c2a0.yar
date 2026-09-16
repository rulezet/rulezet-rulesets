rule TTP_XOR_QUAD_CurrentVersionRun_c2a0 {
  strings:
    $key_c2a0 = { 91 cf [2] b5 c1 [2] 9e ed [2] b0 cf [2] a4 d4 [2] ab ce [2] b5 d3 [2] b7 d2 [2] ac d4 [2] b0 d3 [2] ac fc }

  condition:
    any of them
}