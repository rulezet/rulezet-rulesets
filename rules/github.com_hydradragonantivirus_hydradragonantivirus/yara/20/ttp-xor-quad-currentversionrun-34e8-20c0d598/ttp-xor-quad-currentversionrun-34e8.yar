rule TTP_XOR_QUAD_CurrentVersionRun_34e8 {
  strings:
    $key_34e8 = { 67 87 [2] 43 89 [2] 68 a5 [2] 46 87 [2] 52 9c [2] 5d 86 [2] 43 9b [2] 41 9a [2] 5a 9c [2] 46 9b [2] 5a b4 }

  condition:
    any of them
}