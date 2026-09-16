rule TTP_XOR_QUAD_CurrentVersionRun_0fe8 {
  strings:
    $key_0fe8 = { 5c 87 [2] 78 89 [2] 53 a5 [2] 7d 87 [2] 69 9c [2] 66 86 [2] 78 9b [2] 7a 9a [2] 61 9c [2] 7d 9b [2] 61 b4 }

  condition:
    any of them
}