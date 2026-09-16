rule TTP_XOR_QUAD_CurrentVersionRun_27e8 {
  strings:
    $key_27e8 = { 74 87 [2] 50 89 [2] 7b a5 [2] 55 87 [2] 41 9c [2] 4e 86 [2] 50 9b [2] 52 9a [2] 49 9c [2] 55 9b [2] 49 b4 }

  condition:
    any of them
}