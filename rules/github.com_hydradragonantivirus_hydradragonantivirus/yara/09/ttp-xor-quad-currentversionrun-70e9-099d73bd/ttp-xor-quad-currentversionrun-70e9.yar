rule TTP_XOR_QUAD_CurrentVersionRun_70e9 {
  strings:
    $key_70e9 = { 23 86 [2] 07 88 [2] 2c a4 [2] 02 86 [2] 16 9d [2] 19 87 [2] 07 9a [2] 05 9b [2] 1e 9d [2] 02 9a [2] 1e b5 }

  condition:
    any of them
}