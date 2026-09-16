rule TTP_XOR_QUAD_CurrentVersionRun_fdda {
  strings:
    $key_fdda = { ae b5 [2] 8a bb [2] a1 97 [2] 8f b5 [2] 9b ae [2] 94 b4 [2] 8a a9 [2] 88 a8 [2] 93 ae [2] 8f a9 [2] 93 86 }

  condition:
    any of them
}