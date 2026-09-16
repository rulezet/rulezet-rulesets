rule TTP_XOR_QUAD_CurrentVersionRun_c108 {
  strings:
    $key_c108 = { 92 67 [2] b6 69 [2] 9d 45 [2] b3 67 [2] a7 7c [2] a8 66 [2] b6 7b [2] b4 7a [2] af 7c [2] b3 7b [2] af 54 }

  condition:
    any of them
}