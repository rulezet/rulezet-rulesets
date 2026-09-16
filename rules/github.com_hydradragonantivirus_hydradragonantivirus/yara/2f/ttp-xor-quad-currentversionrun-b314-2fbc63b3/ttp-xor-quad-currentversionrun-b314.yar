rule TTP_XOR_QUAD_CurrentVersionRun_b314 {
  strings:
    $key_b314 = { e0 7b [2] c4 75 [2] ef 59 [2] c1 7b [2] d5 60 [2] da 7a [2] c4 67 [2] c6 66 [2] dd 60 [2] c1 67 [2] dd 48 }

  condition:
    any of them
}