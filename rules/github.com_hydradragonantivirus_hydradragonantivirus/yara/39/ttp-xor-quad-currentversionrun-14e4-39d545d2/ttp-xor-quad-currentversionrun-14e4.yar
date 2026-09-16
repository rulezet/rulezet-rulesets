rule TTP_XOR_QUAD_CurrentVersionRun_14e4 {
  strings:
    $key_14e4 = { 47 8b [2] 63 85 [2] 48 a9 [2] 66 8b [2] 72 90 [2] 7d 8a [2] 63 97 [2] 61 96 [2] 7a 90 [2] 66 97 [2] 7a b8 }

  condition:
    any of them
}