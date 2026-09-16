rule TTP_XOR_QUAD_CurrentVersionRun_c337 {
  strings:
    $key_c337 = { 90 58 [2] b4 56 [2] 9f 7a [2] b1 58 [2] a5 43 [2] aa 59 [2] b4 44 [2] b6 45 [2] ad 43 [2] b1 44 [2] ad 6b }

  condition:
    any of them
}