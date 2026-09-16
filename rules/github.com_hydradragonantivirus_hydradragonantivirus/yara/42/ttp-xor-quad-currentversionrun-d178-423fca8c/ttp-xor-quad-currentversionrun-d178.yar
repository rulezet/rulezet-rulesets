rule TTP_XOR_QUAD_CurrentVersionRun_d178 {
  strings:
    $key_d178 = { 82 17 [2] a6 19 [2] 8d 35 [2] a3 17 [2] b7 0c [2] b8 16 [2] a6 0b [2] a4 0a [2] bf 0c [2] a3 0b [2] bf 24 }

  condition:
    any of them
}