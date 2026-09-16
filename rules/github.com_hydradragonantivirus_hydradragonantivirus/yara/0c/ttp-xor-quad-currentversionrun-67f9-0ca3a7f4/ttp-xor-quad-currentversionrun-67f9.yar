rule TTP_XOR_QUAD_CurrentVersionRun_67f9 {
  strings:
    $key_67f9 = { 34 96 [2] 10 98 [2] 3b b4 [2] 15 96 [2] 01 8d [2] 0e 97 [2] 10 8a [2] 12 8b [2] 09 8d [2] 15 8a [2] 09 a5 }

  condition:
    any of them
}