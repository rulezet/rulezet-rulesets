rule TTP_XOR_QUAD_CurrentVersionRun_0e78 {
  strings:
    $key_0e78 = { 5d 17 [2] 79 19 [2] 52 35 [2] 7c 17 [2] 68 0c [2] 67 16 [2] 79 0b [2] 7b 0a [2] 60 0c [2] 7c 0b [2] 60 24 }

  condition:
    any of them
}