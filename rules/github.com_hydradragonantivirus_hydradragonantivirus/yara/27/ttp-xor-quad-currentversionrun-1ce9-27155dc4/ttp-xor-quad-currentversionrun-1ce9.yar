rule TTP_XOR_QUAD_CurrentVersionRun_1ce9 {
  strings:
    $key_1ce9 = { 4f 86 [2] 6b 88 [2] 40 a4 [2] 6e 86 [2] 7a 9d [2] 75 87 [2] 6b 9a [2] 69 9b [2] 72 9d [2] 6e 9a [2] 72 b5 }

  condition:
    any of them
}