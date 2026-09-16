rule TTP_XOR_QUAD_CurrentVersionRun_51f8 {
  strings:
    $key_51f8 = { 02 97 [2] 26 99 [2] 0d b5 [2] 23 97 [2] 37 8c [2] 38 96 [2] 26 8b [2] 24 8a [2] 3f 8c [2] 23 8b [2] 3f a4 }

  condition:
    any of them
}