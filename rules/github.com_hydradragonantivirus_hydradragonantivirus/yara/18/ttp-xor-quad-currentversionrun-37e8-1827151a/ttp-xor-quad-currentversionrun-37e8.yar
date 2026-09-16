rule TTP_XOR_QUAD_CurrentVersionRun_37e8 {
  strings:
    $key_37e8 = { 64 87 [2] 40 89 [2] 6b a5 [2] 45 87 [2] 51 9c [2] 5e 86 [2] 40 9b [2] 42 9a [2] 59 9c [2] 45 9b [2] 59 b4 }

  condition:
    any of them
}