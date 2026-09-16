rule TTP_XOR_QUAD_CurrentVersionRun_c14b {
  strings:
    $key_c14b = { 92 24 [2] b6 2a [2] 9d 06 [2] b3 24 [2] a7 3f [2] a8 25 [2] b6 38 [2] b4 39 [2] af 3f [2] b3 38 [2] af 17 }

  condition:
    any of them
}