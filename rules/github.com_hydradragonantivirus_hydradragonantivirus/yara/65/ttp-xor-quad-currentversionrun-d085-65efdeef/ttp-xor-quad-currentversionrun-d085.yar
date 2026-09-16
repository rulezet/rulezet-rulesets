rule TTP_XOR_QUAD_CurrentVersionRun_d085 {
  strings:
    $key_d085 = { 83 ea [2] a7 e4 [2] 8c c8 [2] a2 ea [2] b6 f1 [2] b9 eb [2] a7 f6 [2] a5 f7 [2] be f1 [2] a2 f6 [2] be d9 }

  condition:
    any of them
}