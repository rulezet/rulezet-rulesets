rule TTP_XOR_QUAD_CurrentVersionRun_2ada {
  strings:
    $key_2ada = { 79 b5 [2] 5d bb [2] 76 97 [2] 58 b5 [2] 4c ae [2] 43 b4 [2] 5d a9 [2] 5f a8 [2] 44 ae [2] 58 a9 [2] 44 86 }

  condition:
    any of them
}