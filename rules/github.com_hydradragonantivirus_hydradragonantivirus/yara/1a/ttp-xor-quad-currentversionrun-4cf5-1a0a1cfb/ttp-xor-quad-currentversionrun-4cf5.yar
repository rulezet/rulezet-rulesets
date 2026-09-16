rule TTP_XOR_QUAD_CurrentVersionRun_4cf5 {
  strings:
    $key_4cf5 = { 1f 9a [2] 3b 94 [2] 10 b8 [2] 3e 9a [2] 2a 81 [2] 25 9b [2] 3b 86 [2] 39 87 [2] 22 81 [2] 3e 86 [2] 22 a9 }

  condition:
    any of them
}