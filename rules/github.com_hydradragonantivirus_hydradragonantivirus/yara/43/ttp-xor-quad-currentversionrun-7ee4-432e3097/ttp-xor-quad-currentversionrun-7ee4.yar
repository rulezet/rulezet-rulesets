rule TTP_XOR_QUAD_CurrentVersionRun_7ee4 {
  strings:
    $key_7ee4 = { 2d 8b [2] 09 85 [2] 22 a9 [2] 0c 8b [2] 18 90 [2] 17 8a [2] 09 97 [2] 0b 96 [2] 10 90 [2] 0c 97 [2] 10 b8 }

  condition:
    any of them
}