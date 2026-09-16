rule TTP_XOR_QUAD_CurrentVersionRun_36f8 {
  strings:
    $key_36f8 = { 65 97 [2] 41 99 [2] 6a b5 [2] 44 97 [2] 50 8c [2] 5f 96 [2] 41 8b [2] 43 8a [2] 58 8c [2] 44 8b [2] 58 a4 }

  condition:
    any of them
}