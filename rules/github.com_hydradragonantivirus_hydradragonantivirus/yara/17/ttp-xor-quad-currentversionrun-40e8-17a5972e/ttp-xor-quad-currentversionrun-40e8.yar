rule TTP_XOR_QUAD_CurrentVersionRun_40e8 {
  strings:
    $key_40e8 = { 13 87 [2] 37 89 [2] 1c a5 [2] 32 87 [2] 26 9c [2] 29 86 [2] 37 9b [2] 35 9a [2] 2e 9c [2] 32 9b [2] 2e b4 }

  condition:
    any of them
}