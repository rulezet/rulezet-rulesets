rule TTP_XOR_QUAD_CurrentVersionRun_7ee9 {
  strings:
    $key_7ee9 = { 2d 86 [2] 09 88 [2] 22 a4 [2] 0c 86 [2] 18 9d [2] 17 87 [2] 09 9a [2] 0b 9b [2] 10 9d [2] 0c 9a [2] 10 b5 }

  condition:
    any of them
}