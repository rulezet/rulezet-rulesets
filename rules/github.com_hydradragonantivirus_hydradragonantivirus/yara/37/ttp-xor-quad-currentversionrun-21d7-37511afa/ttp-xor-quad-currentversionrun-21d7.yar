rule TTP_XOR_QUAD_CurrentVersionRun_21d7 {
  strings:
    $key_21d7 = { 72 b8 [2] 56 b6 [2] 7d 9a [2] 53 b8 [2] 47 a3 [2] 48 b9 [2] 56 a4 [2] 54 a5 [2] 4f a3 [2] 53 a4 [2] 4f 8b }

  condition:
    any of them
}