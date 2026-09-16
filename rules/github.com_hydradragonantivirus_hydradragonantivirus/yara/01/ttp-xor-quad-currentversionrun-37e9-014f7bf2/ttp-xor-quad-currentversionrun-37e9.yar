rule TTP_XOR_QUAD_CurrentVersionRun_37e9 {
  strings:
    $key_37e9 = { 64 86 [2] 40 88 [2] 6b a4 [2] 45 86 [2] 51 9d [2] 5e 87 [2] 40 9a [2] 42 9b [2] 59 9d [2] 45 9a [2] 59 b5 }

  condition:
    any of them
}