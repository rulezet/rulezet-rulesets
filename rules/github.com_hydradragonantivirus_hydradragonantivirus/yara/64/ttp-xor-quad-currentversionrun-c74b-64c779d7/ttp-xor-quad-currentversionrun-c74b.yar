rule TTP_XOR_QUAD_CurrentVersionRun_c74b {
  strings:
    $key_c74b = { 94 24 [2] b0 2a [2] 9b 06 [2] b5 24 [2] a1 3f [2] ae 25 [2] b0 38 [2] b2 39 [2] a9 3f [2] b5 38 [2] a9 17 }

  condition:
    any of them
}