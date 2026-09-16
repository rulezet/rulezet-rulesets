rule TTP_XOR_QUAD_CurrentVersionRun_e6d6 {
  strings:
    $key_e6d6 = { b5 b9 [2] 91 b7 [2] ba 9b [2] 94 b9 [2] 80 a2 [2] 8f b8 [2] 91 a5 [2] 93 a4 [2] 88 a2 [2] 94 a5 [2] 88 8a }

  condition:
    any of them
}