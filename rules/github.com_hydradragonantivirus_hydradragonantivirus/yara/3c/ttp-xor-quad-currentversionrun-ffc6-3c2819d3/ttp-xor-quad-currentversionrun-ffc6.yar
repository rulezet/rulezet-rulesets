rule TTP_XOR_QUAD_CurrentVersionRun_ffc6 {
  strings:
    $key_ffc6 = { ac a9 [2] 88 a7 [2] a3 8b [2] 8d a9 [2] 99 b2 [2] 96 a8 [2] 88 b5 [2] 8a b4 [2] 91 b2 [2] 8d b5 [2] 91 9a }

  condition:
    any of them
}