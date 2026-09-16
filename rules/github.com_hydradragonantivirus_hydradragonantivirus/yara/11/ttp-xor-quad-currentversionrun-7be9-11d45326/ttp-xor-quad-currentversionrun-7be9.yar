rule TTP_XOR_QUAD_CurrentVersionRun_7be9 {
  strings:
    $key_7be9 = { 28 86 [2] 0c 88 [2] 27 a4 [2] 09 86 [2] 1d 9d [2] 12 87 [2] 0c 9a [2] 0e 9b [2] 15 9d [2] 09 9a [2] 15 b5 }

  condition:
    any of them
}