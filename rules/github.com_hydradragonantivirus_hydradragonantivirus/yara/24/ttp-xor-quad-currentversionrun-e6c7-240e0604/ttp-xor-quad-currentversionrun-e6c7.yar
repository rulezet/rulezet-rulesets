rule TTP_XOR_QUAD_CurrentVersionRun_e6c7 {
  strings:
    $key_e6c7 = { b5 a8 [2] 91 a6 [2] ba 8a [2] 94 a8 [2] 80 b3 [2] 8f a9 [2] 91 b4 [2] 93 b5 [2] 88 b3 [2] 94 b4 [2] 88 9b }

  condition:
    any of them
}