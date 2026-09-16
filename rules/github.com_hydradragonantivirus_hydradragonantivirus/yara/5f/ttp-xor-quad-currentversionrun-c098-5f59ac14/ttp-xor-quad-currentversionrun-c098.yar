rule TTP_XOR_QUAD_CurrentVersionRun_c098 {
  strings:
    $key_c098 = { 93 f7 [2] b7 f9 [2] 9c d5 [2] b2 f7 [2] a6 ec [2] a9 f6 [2] b7 eb [2] b5 ea [2] ae ec [2] b2 eb [2] ae c4 }

  condition:
    any of them
}