rule TTP_XOR_QUAD_CurrentVersionRun_49e8 {
  strings:
    $key_49e8 = { 1a 87 [2] 3e 89 [2] 15 a5 [2] 3b 87 [2] 2f 9c [2] 20 86 [2] 3e 9b [2] 3c 9a [2] 27 9c [2] 3b 9b [2] 27 b4 }

  condition:
    any of them
}