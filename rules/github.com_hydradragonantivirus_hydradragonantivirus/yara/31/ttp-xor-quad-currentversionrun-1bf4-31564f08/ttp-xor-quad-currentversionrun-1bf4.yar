rule TTP_XOR_QUAD_CurrentVersionRun_1bf4 {
  strings:
    $key_1bf4 = { 48 9b [2] 6c 95 [2] 47 b9 [2] 69 9b [2] 7d 80 [2] 72 9a [2] 6c 87 [2] 6e 86 [2] 75 80 [2] 69 87 [2] 75 a8 }

  condition:
    any of them
}