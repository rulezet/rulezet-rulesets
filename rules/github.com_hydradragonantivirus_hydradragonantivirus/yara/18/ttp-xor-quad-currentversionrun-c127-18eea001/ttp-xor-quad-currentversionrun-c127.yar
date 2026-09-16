rule TTP_XOR_QUAD_CurrentVersionRun_c127 {
  strings:
    $key_c127 = { 92 48 [2] b6 46 [2] 9d 6a [2] b3 48 [2] a7 53 [2] a8 49 [2] b6 54 [2] b4 55 [2] af 53 [2] b3 54 [2] af 7b }

  condition:
    any of them
}