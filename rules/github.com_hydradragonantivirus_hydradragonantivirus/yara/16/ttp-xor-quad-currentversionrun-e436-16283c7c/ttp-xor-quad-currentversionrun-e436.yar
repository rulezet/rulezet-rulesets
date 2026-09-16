rule TTP_XOR_QUAD_CurrentVersionRun_e436 {
  strings:
    $key_e436 = { b7 59 [2] 93 57 [2] b8 7b [2] 96 59 [2] 82 42 [2] 8d 58 [2] 93 45 [2] 91 44 [2] 8a 42 [2] 96 45 [2] 8a 6a }

  condition:
    any of them
}