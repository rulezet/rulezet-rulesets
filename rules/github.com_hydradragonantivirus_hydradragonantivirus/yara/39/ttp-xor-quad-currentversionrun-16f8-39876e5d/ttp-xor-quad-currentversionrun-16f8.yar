rule TTP_XOR_QUAD_CurrentVersionRun_16f8 {
  strings:
    $key_16f8 = { 45 97 [2] 61 99 [2] 4a b5 [2] 64 97 [2] 70 8c [2] 7f 96 [2] 61 8b [2] 63 8a [2] 78 8c [2] 64 8b [2] 78 a4 }

  condition:
    any of them
}