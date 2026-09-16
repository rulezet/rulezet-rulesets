rule TTP_XOR_QUAD_CurrentVersionRun_00e8 {
  strings:
    $key_00e8 = { 53 87 [2] 77 89 [2] 5c a5 [2] 72 87 [2] 66 9c [2] 69 86 [2] 77 9b [2] 75 9a [2] 6e 9c [2] 72 9b [2] 6e b4 }

  condition:
    any of them
}