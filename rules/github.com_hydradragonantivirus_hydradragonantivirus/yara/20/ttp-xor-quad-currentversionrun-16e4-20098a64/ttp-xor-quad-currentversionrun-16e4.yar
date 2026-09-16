rule TTP_XOR_QUAD_CurrentVersionRun_16e4 {
  strings:
    $key_16e4 = { 45 8b [2] 61 85 [2] 4a a9 [2] 64 8b [2] 70 90 [2] 7f 8a [2] 61 97 [2] 63 96 [2] 78 90 [2] 64 97 [2] 78 b8 }

  condition:
    any of them
}