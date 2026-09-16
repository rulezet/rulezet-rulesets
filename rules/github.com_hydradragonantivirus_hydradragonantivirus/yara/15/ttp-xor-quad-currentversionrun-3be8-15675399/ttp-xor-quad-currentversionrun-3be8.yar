rule TTP_XOR_QUAD_CurrentVersionRun_3be8 {
  strings:
    $key_3be8 = { 68 87 [2] 4c 89 [2] 67 a5 [2] 49 87 [2] 5d 9c [2] 52 86 [2] 4c 9b [2] 4e 9a [2] 55 9c [2] 49 9b [2] 55 b4 }

  condition:
    any of them
}