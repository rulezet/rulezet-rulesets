rule TTP_XOR_QUAD_CurrentVersionRun_e4e9 {
  strings:
    $key_e4e9 = { b7 86 [2] 93 88 [2] b8 a4 [2] 96 86 [2] 82 9d [2] 8d 87 [2] 93 9a [2] 91 9b [2] 8a 9d [2] 96 9a [2] 8a b5 }

  condition:
    any of them
}