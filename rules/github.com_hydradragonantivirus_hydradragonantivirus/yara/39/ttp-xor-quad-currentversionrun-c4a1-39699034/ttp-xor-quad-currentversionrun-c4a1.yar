rule TTP_XOR_QUAD_CurrentVersionRun_c4a1 {
  strings:
    $key_c4a1 = { 97 ce [2] b3 c0 [2] 98 ec [2] b6 ce [2] a2 d5 [2] ad cf [2] b3 d2 [2] b1 d3 [2] aa d5 [2] b6 d2 [2] aa fd }

  condition:
    any of them
}