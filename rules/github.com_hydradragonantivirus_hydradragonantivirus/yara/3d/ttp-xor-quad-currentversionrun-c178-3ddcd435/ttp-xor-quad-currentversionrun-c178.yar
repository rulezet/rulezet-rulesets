rule TTP_XOR_QUAD_CurrentVersionRun_c178 {
  strings:
    $key_c178 = { 92 17 [2] b6 19 [2] 9d 35 [2] b3 17 [2] a7 0c [2] a8 16 [2] b6 0b [2] b4 0a [2] af 0c [2] b3 0b [2] af 24 }

  condition:
    any of them
}