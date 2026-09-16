rule TTP_XOR_QUAD_CurrentVersionRun_78e9 {
  strings:
    $key_78e9 = { 2b 86 [2] 0f 88 [2] 24 a4 [2] 0a 86 [2] 1e 9d [2] 11 87 [2] 0f 9a [2] 0d 9b [2] 16 9d [2] 0a 9a [2] 16 b5 }

  condition:
    any of them
}