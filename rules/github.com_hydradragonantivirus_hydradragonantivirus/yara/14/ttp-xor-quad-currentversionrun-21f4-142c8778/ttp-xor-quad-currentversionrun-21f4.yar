rule TTP_XOR_QUAD_CurrentVersionRun_21f4 {
  strings:
    $key_21f4 = { 72 9b [2] 56 95 [2] 7d b9 [2] 53 9b [2] 47 80 [2] 48 9a [2] 56 87 [2] 54 86 [2] 4f 80 [2] 53 87 [2] 4f a8 }

  condition:
    any of them
}