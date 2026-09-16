rule TTP_XOR_QUAD_CurrentVersionRun_c147 {
  strings:
    $key_c147 = { 92 28 [2] b6 26 [2] 9d 0a [2] b3 28 [2] a7 33 [2] a8 29 [2] b6 34 [2] b4 35 [2] af 33 [2] b3 34 [2] af 1b }

  condition:
    any of them
}