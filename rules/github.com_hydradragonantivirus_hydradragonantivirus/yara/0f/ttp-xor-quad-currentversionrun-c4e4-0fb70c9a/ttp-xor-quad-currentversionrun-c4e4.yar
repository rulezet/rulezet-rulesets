rule TTP_XOR_QUAD_CurrentVersionRun_c4e4 {
  strings:
    $key_c4e4 = { 97 8b [2] b3 85 [2] 98 a9 [2] b6 8b [2] a2 90 [2] ad 8a [2] b3 97 [2] b1 96 [2] aa 90 [2] b6 97 [2] aa b8 }

  condition:
    any of them
}