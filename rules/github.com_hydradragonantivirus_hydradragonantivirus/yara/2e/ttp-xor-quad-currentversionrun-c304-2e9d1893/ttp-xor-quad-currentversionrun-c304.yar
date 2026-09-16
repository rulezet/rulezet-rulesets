rule TTP_XOR_QUAD_CurrentVersionRun_c304 {
  strings:
    $key_c304 = { 90 6b [2] b4 65 [2] 9f 49 [2] b1 6b [2] a5 70 [2] aa 6a [2] b4 77 [2] b6 76 [2] ad 70 [2] b1 77 [2] ad 58 }

  condition:
    any of them
}