rule TTP_XOR_QUAD_CurrentVersionRun_e4e8 {
  strings:
    $key_e4e8 = { b7 87 [2] 93 89 [2] b8 a5 [2] 96 87 [2] 82 9c [2] 8d 86 [2] 93 9b [2] 91 9a [2] 8a 9c [2] 96 9b [2] 8a b4 }

  condition:
    any of them
}