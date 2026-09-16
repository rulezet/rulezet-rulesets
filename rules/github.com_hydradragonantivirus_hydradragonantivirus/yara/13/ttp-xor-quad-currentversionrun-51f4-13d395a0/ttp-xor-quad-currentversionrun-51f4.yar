rule TTP_XOR_QUAD_CurrentVersionRun_51f4 {
  strings:
    $key_51f4 = { 02 9b [2] 26 95 [2] 0d b9 [2] 23 9b [2] 37 80 [2] 38 9a [2] 26 87 [2] 24 86 [2] 3f 80 [2] 23 87 [2] 3f a8 }

  condition:
    any of them
}