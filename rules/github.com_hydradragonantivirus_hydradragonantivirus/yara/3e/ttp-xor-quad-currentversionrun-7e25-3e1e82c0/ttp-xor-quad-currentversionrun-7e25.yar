rule TTP_XOR_QUAD_CurrentVersionRun_7e25 {
  strings:
    $key_7e25 = { 2d 4a [2] 09 44 [2] 22 68 [2] 0c 4a [2] 18 51 [2] 17 4b [2] 09 56 [2] 0b 57 [2] 10 51 [2] 0c 56 [2] 10 79 }

  condition:
    any of them
}