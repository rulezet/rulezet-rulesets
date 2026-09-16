rule TTP_XOR_QUAD_CurrentVersionRun_1b25 {
  strings:
    $key_1b25 = { 48 4a [2] 6c 44 [2] 47 68 [2] 69 4a [2] 7d 51 [2] 72 4b [2] 6c 56 [2] 6e 57 [2] 75 51 [2] 69 56 [2] 75 79 }

  condition:
    any of them
}