rule TTP_XOR_QUAD_CurrentVersionRun_1fe8 {
  strings:
    $key_1fe8 = { 4c 87 [2] 68 89 [2] 43 a5 [2] 6d 87 [2] 79 9c [2] 76 86 [2] 68 9b [2] 6a 9a [2] 71 9c [2] 6d 9b [2] 71 b4 }

  condition:
    any of them
}