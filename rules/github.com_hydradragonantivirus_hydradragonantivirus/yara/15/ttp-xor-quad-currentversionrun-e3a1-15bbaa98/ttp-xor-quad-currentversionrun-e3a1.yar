rule TTP_XOR_QUAD_CurrentVersionRun_e3a1 {
  strings:
    $key_e3a1 = { b0 ce [2] 94 c0 [2] bf ec [2] 91 ce [2] 85 d5 [2] 8a cf [2] 94 d2 [2] 96 d3 [2] 8d d5 [2] 91 d2 [2] 8d fd }

  condition:
    any of them
}