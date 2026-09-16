rule TTP_XOR_QUAD_CurrentVersionRun_21f8 {
  strings:
    $key_21f8 = { 72 97 [2] 56 99 [2] 7d b5 [2] 53 97 [2] 47 8c [2] 48 96 [2] 56 8b [2] 54 8a [2] 4f 8c [2] 53 8b [2] 4f a4 }

  condition:
    any of them
}