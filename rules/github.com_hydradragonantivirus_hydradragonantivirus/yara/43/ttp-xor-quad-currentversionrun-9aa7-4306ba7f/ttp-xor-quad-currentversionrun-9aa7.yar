rule TTP_XOR_QUAD_CurrentVersionRun_9aa7 {
  strings:
    $key_9aa7 = { c9 c8 [2] ed c6 [2] c6 ea [2] e8 c8 [2] fc d3 [2] f3 c9 [2] ed d4 [2] ef d5 [2] f4 d3 [2] e8 d4 [2] f4 fb }

  condition:
    any of them
}