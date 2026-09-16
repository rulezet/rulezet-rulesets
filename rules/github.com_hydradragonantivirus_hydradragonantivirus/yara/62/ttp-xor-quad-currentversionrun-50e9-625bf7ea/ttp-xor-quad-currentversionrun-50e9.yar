rule TTP_XOR_QUAD_CurrentVersionRun_50e9 {
  strings:
    $key_50e9 = { 03 86 [2] 27 88 [2] 0c a4 [2] 22 86 [2] 36 9d [2] 39 87 [2] 27 9a [2] 25 9b [2] 3e 9d [2] 22 9a [2] 3e b5 }

  condition:
    any of them
}