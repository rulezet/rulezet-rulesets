rule TTP_XOR_QUAD_CurrentVersionRun_cca1 {
  strings:
    $key_cca1 = { 9f ce [2] bb c0 [2] 90 ec [2] be ce [2] aa d5 [2] a5 cf [2] bb d2 [2] b9 d3 [2] a2 d5 [2] be d2 [2] a2 fd }

  condition:
    any of them
}