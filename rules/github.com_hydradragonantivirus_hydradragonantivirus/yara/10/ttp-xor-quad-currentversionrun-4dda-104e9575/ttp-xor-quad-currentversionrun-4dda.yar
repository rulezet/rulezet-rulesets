rule TTP_XOR_QUAD_CurrentVersionRun_4dda {
  strings:
    $key_4dda = { 1e b5 [2] 3a bb [2] 11 97 [2] 3f b5 [2] 2b ae [2] 24 b4 [2] 3a a9 [2] 38 a8 [2] 23 ae [2] 3f a9 [2] 23 86 }

  condition:
    any of them
}