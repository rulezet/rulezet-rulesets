rule TTP_XOR_QUAD_CurrentVersionRun_c336 {
  strings:
    $key_c336 = { 90 59 [2] b4 57 [2] 9f 7b [2] b1 59 [2] a5 42 [2] aa 58 [2] b4 45 [2] b6 44 [2] ad 42 [2] b1 45 [2] ad 6a }

  condition:
    any of them
}