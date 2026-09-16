rule TTP_XOR_QUAD_CurrentVersionRun_0e45 {
  strings:
    $key_0e45 = { 5d 2a [2] 79 24 [2] 52 08 [2] 7c 2a [2] 68 31 [2] 67 2b [2] 79 36 [2] 7b 37 [2] 60 31 [2] 7c 36 [2] 60 19 }

  condition:
    any of them
}