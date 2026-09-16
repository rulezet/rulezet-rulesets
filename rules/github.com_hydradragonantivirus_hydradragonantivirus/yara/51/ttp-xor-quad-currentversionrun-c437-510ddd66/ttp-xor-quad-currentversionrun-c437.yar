rule TTP_XOR_QUAD_CurrentVersionRun_c437 {
  strings:
    $key_c437 = { 97 58 [2] b3 56 [2] 98 7a [2] b6 58 [2] a2 43 [2] ad 59 [2] b3 44 [2] b1 45 [2] aa 43 [2] b6 44 [2] aa 6b }

  condition:
    any of them
}