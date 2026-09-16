rule TTP_XOR_QUAD_CurrentVersionRun_edda {
  strings:
    $key_edda = { be b5 [2] 9a bb [2] b1 97 [2] 9f b5 [2] 8b ae [2] 84 b4 [2] 9a a9 [2] 98 a8 [2] 83 ae [2] 9f a9 [2] 83 86 }

  condition:
    any of them
}