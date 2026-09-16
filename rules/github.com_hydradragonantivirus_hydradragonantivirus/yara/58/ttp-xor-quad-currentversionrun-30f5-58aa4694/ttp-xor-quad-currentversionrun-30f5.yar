rule TTP_XOR_QUAD_CurrentVersionRun_30f5 {
  strings:
    $key_30f5 = { 63 9a [2] 47 94 [2] 6c b8 [2] 42 9a [2] 56 81 [2] 59 9b [2] 47 86 [2] 45 87 [2] 5e 81 [2] 42 86 [2] 5e a9 }

  condition:
    any of them
}