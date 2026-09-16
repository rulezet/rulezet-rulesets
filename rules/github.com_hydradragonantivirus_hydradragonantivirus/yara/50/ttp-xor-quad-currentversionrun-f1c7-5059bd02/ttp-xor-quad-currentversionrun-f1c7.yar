rule TTP_XOR_QUAD_CurrentVersionRun_f1c7 {
  strings:
    $key_f1c7 = { a2 a8 [2] 86 a6 [2] ad 8a [2] 83 a8 [2] 97 b3 [2] 98 a9 [2] 86 b4 [2] 84 b5 [2] 9f b3 [2] 83 b4 [2] 9f 9b }

  condition:
    any of them
}