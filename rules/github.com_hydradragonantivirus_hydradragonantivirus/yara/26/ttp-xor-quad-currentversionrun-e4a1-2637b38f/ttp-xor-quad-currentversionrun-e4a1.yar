rule TTP_XOR_QUAD_CurrentVersionRun_e4a1 {
  strings:
    $key_e4a1 = { b7 ce [2] 93 c0 [2] b8 ec [2] 96 ce [2] 82 d5 [2] 8d cf [2] 93 d2 [2] 91 d3 [2] 8a d5 [2] 96 d2 [2] 8a fd }

  condition:
    any of them
}