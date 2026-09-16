rule TTP_XOR_QUAD_CurrentVersionRun_11d6 {
  strings:
    $key_11d6 = { 42 b9 [2] 66 b7 [2] 4d 9b [2] 63 b9 [2] 77 a2 [2] 78 b8 [2] 66 a5 [2] 64 a4 [2] 7f a2 [2] 63 a5 [2] 7f 8a }

  condition:
    any of them
}