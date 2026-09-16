rule TTP_XOR_QUAD_CurrentVersionRun_57f8 {
  strings:
    $key_57f8 = { 04 97 [2] 20 99 [2] 0b b5 [2] 25 97 [2] 31 8c [2] 3e 96 [2] 20 8b [2] 22 8a [2] 39 8c [2] 25 8b [2] 39 a4 }

  condition:
    any of them
}