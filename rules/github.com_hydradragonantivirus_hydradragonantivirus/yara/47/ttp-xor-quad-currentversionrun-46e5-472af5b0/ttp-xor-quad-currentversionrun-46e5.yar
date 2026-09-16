rule TTP_XOR_QUAD_CurrentVersionRun_46e5 {
  strings:
    $key_46e5 = { 15 8a [2] 31 84 [2] 1a a8 [2] 34 8a [2] 20 91 [2] 2f 8b [2] 31 96 [2] 33 97 [2] 28 91 [2] 34 96 [2] 28 b9 }

  condition:
    any of them
}