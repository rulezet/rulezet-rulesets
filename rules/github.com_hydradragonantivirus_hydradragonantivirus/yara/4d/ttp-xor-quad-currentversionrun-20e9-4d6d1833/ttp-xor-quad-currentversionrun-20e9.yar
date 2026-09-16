rule TTP_XOR_QUAD_CurrentVersionRun_20e9 {
  strings:
    $key_20e9 = { 73 86 [2] 57 88 [2] 7c a4 [2] 52 86 [2] 46 9d [2] 49 87 [2] 57 9a [2] 55 9b [2] 4e 9d [2] 52 9a [2] 4e b5 }

  condition:
    any of them
}