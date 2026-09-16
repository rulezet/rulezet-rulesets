rule TTP_XOR_QUAD_CurrentVersionRun_31f8 {
  strings:
    $key_31f8 = { 62 97 [2] 46 99 [2] 6d b5 [2] 43 97 [2] 57 8c [2] 58 96 [2] 46 8b [2] 44 8a [2] 5f 8c [2] 43 8b [2] 5f a4 }

  condition:
    any of them
}