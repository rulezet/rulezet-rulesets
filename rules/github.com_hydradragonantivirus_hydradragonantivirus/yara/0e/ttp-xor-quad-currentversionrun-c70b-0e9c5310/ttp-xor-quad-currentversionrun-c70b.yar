rule TTP_XOR_QUAD_CurrentVersionRun_c70b {
  strings:
    $key_c70b = { 94 64 [2] b0 6a [2] 9b 46 [2] b5 64 [2] a1 7f [2] ae 65 [2] b0 78 [2] b2 79 [2] a9 7f [2] b5 78 [2] a9 57 }

  condition:
    any of them
}