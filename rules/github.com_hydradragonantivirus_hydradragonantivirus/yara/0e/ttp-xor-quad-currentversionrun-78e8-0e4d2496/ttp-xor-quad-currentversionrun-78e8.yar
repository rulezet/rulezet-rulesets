rule TTP_XOR_QUAD_CurrentVersionRun_78e8 {
  strings:
    $key_78e8 = { 2b 87 [2] 0f 89 [2] 24 a5 [2] 0a 87 [2] 1e 9c [2] 11 86 [2] 0f 9b [2] 0d 9a [2] 16 9c [2] 0a 9b [2] 16 b4 }

  condition:
    any of them
}