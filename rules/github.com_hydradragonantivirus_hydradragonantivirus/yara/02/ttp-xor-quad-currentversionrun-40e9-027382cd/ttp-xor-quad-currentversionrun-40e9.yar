rule TTP_XOR_QUAD_CurrentVersionRun_40e9 {
  strings:
    $key_40e9 = { 13 86 [2] 37 88 [2] 1c a4 [2] 32 86 [2] 26 9d [2] 29 87 [2] 37 9a [2] 35 9b [2] 2e 9d [2] 32 9a [2] 2e b5 }

  condition:
    any of them
}