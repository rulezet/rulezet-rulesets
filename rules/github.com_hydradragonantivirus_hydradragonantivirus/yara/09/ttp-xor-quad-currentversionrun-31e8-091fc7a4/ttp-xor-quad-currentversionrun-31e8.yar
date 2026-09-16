rule TTP_XOR_QUAD_CurrentVersionRun_31e8 {
  strings:
    $key_31e8 = { 62 87 [2] 46 89 [2] 6d a5 [2] 43 87 [2] 57 9c [2] 58 86 [2] 46 9b [2] 44 9a [2] 5f 9c [2] 43 9b [2] 5f b4 }

  condition:
    any of them
}