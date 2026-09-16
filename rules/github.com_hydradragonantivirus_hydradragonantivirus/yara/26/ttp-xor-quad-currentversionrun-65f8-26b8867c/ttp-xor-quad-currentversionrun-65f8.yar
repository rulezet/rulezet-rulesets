rule TTP_XOR_QUAD_CurrentVersionRun_65f8 {
  strings:
    $key_65f8 = { 36 97 [2] 12 99 [2] 39 b5 [2] 17 97 [2] 03 8c [2] 0c 96 [2] 12 8b [2] 10 8a [2] 0b 8c [2] 17 8b [2] 0b a4 }

  condition:
    any of them
}