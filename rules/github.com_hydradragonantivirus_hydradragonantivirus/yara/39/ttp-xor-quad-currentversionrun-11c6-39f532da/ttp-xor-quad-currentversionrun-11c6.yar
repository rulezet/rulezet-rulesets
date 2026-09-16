rule TTP_XOR_QUAD_CurrentVersionRun_11c6 {
  strings:
    $key_11c6 = { 42 a9 [2] 66 a7 [2] 4d 8b [2] 63 a9 [2] 77 b2 [2] 78 a8 [2] 66 b5 [2] 64 b4 [2] 7f b2 [2] 63 b5 [2] 7f 9a }

  condition:
    any of them
}