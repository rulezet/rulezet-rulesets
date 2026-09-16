rule TTP_XOR_QUAD_CurrentVersionRun_3dda {
  strings:
    $key_3dda = { 6e b5 [2] 4a bb [2] 61 97 [2] 4f b5 [2] 5b ae [2] 54 b4 [2] 4a a9 [2] 48 a8 [2] 53 ae [2] 4f a9 [2] 53 86 }

  condition:
    any of them
}