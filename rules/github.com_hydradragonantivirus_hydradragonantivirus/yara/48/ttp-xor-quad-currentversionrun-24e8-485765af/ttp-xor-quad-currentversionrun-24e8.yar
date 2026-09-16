rule TTP_XOR_QUAD_CurrentVersionRun_24e8 {
  strings:
    $key_24e8 = { 77 87 [2] 53 89 [2] 78 a5 [2] 56 87 [2] 42 9c [2] 4d 86 [2] 53 9b [2] 51 9a [2] 4a 9c [2] 56 9b [2] 4a b4 }

  condition:
    any of them
}