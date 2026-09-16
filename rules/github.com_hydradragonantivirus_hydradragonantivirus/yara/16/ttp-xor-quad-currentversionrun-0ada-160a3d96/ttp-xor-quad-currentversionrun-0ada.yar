rule TTP_XOR_QUAD_CurrentVersionRun_0ada {
  strings:
    $key_0ada = { 59 b5 [2] 7d bb [2] 56 97 [2] 78 b5 [2] 6c ae [2] 63 b4 [2] 7d a9 [2] 7f a8 [2] 64 ae [2] 78 a9 [2] 64 86 }

  condition:
    any of them
}