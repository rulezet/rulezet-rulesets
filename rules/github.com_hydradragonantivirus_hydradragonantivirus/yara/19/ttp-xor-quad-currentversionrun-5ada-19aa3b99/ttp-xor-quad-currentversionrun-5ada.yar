rule TTP_XOR_QUAD_CurrentVersionRun_5ada {
  strings:
    $key_5ada = { 09 b5 [2] 2d bb [2] 06 97 [2] 28 b5 [2] 3c ae [2] 33 b4 [2] 2d a9 [2] 2f a8 [2] 34 ae [2] 28 a9 [2] 34 86 }

  condition:
    any of them
}