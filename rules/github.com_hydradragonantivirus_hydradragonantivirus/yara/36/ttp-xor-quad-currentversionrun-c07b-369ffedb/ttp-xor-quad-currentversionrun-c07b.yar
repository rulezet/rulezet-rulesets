rule TTP_XOR_QUAD_CurrentVersionRun_c07b {
  strings:
    $key_c07b = { 93 14 [2] b7 1a [2] 9c 36 [2] b2 14 [2] a6 0f [2] a9 15 [2] b7 08 [2] b5 09 [2] ae 0f [2] b2 08 [2] ae 27 }

  condition:
    any of them
}