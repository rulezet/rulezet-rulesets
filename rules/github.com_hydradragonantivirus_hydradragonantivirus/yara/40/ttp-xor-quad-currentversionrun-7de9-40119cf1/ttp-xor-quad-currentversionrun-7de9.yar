rule TTP_XOR_QUAD_CurrentVersionRun_7de9 {
  strings:
    $key_7de9 = { 2e 86 [2] 0a 88 [2] 21 a4 [2] 0f 86 [2] 1b 9d [2] 14 87 [2] 0a 9a [2] 08 9b [2] 13 9d [2] 0f 9a [2] 13 b5 }

  condition:
    any of them
}