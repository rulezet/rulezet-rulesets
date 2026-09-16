rule TTP_XOR_QUAD_CurrentVersionRun_20e8 {
  strings:
    $key_20e8 = { 73 87 [2] 57 89 [2] 7c a5 [2] 52 87 [2] 46 9c [2] 49 86 [2] 57 9b [2] 55 9a [2] 4e 9c [2] 52 9b [2] 4e b4 }

  condition:
    any of them
}