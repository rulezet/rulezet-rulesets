rule TTP_XOR_QUAD_CurrentVersionRun_bea7 {
  strings:
    $key_bea7 = { ed c8 [2] c9 c6 [2] e2 ea [2] cc c8 [2] d8 d3 [2] d7 c9 [2] c9 d4 [2] cb d5 [2] d0 d3 [2] cc d4 [2] d0 fb }

  condition:
    any of them
}