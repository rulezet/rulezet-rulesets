rule TTP_XOR_QUAD_CurrentVersionRun_c798 {
  strings:
    $key_c798 = { 94 f7 [2] b0 f9 [2] 9b d5 [2] b5 f7 [2] a1 ec [2] ae f6 [2] b0 eb [2] b2 ea [2] a9 ec [2] b5 eb [2] a9 c4 }

  condition:
    any of them
}