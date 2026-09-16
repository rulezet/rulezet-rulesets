rule TTP_XOR_QUAD_CurrentVersionRun_30e4 {
  strings:
    $key_30e4 = { 63 8b [2] 47 85 [2] 6c a9 [2] 42 8b [2] 56 90 [2] 59 8a [2] 47 97 [2] 45 96 [2] 5e 90 [2] 42 97 [2] 5e b8 }

  condition:
    any of them
}