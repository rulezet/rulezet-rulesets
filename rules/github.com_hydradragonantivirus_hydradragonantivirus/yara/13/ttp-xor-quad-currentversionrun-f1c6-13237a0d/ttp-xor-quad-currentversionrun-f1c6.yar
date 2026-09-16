rule TTP_XOR_QUAD_CurrentVersionRun_f1c6 {
  strings:
    $key_f1c6 = { a2 a9 [2] 86 a7 [2] ad 8b [2] 83 a9 [2] 97 b2 [2] 98 a8 [2] 86 b5 [2] 84 b4 [2] 9f b2 [2] 83 b5 [2] 9f 9a }

  condition:
    any of them
}