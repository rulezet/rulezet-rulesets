rule TTP_XOR_QUAD_CurrentVersionRun_0ff5 {
  strings:
    $key_0ff5 = { 5c 9a [2] 78 94 [2] 53 b8 [2] 7d 9a [2] 69 81 [2] 66 9b [2] 78 86 [2] 7a 87 [2] 61 81 [2] 7d 86 [2] 61 a9 }

  condition:
    any of them
}