rule TTP_XOR_QUAD_CurrentVersionRun_0fe9 {
  strings:
    $key_0fe9 = { 5c 86 [2] 78 88 [2] 53 a4 [2] 7d 86 [2] 69 9d [2] 66 87 [2] 78 9a [2] 7a 9b [2] 61 9d [2] 7d 9a [2] 61 b5 }

  condition:
    any of them
}