rule TTP_XOR_QUAD_CurrentVersionRun_f1e4 {
  strings:
    $key_f1e4 = { a2 8b [2] 86 85 [2] ad a9 [2] 83 8b [2] 97 90 [2] 98 8a [2] 86 97 [2] 84 96 [2] 9f 90 [2] 83 97 [2] 9f b8 }

  condition:
    any of them
}