rule TTP_XOR_QUAD_CurrentVersionRun_50e4 {
  strings:
    $key_50e4 = { 03 8b [2] 27 85 [2] 0c a9 [2] 22 8b [2] 36 90 [2] 39 8a [2] 27 97 [2] 25 96 [2] 3e 90 [2] 22 97 [2] 3e b8 }

  condition:
    any of them
}