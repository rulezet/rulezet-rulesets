rule TTP_XOR_QUAD_CurrentVersionRun_50e8 {
  strings:
    $key_50e8 = { 03 87 [2] 27 89 [2] 0c a5 [2] 22 87 [2] 36 9c [2] 39 86 [2] 27 9b [2] 25 9a [2] 3e 9c [2] 22 9b [2] 3e b4 }

  condition:
    any of them
}