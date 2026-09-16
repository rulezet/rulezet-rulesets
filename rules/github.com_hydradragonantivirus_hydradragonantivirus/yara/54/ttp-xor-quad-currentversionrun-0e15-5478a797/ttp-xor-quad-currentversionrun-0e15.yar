rule TTP_XOR_QUAD_CurrentVersionRun_0e15 {
  strings:
    $key_0e15 = { 5d 7a [2] 79 74 [2] 52 58 [2] 7c 7a [2] 68 61 [2] 67 7b [2] 79 66 [2] 7b 67 [2] 60 61 [2] 7c 66 [2] 60 49 }

  condition:
    any of them
}