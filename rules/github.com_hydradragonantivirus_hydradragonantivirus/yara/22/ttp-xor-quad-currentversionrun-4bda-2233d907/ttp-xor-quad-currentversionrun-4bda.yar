rule TTP_XOR_QUAD_CurrentVersionRun_4bda {
  strings:
    $key_4bda = { 18 b5 [2] 3c bb [2] 17 97 [2] 39 b5 [2] 2d ae [2] 22 b4 [2] 3c a9 [2] 3e a8 [2] 25 ae [2] 39 a9 [2] 25 86 }

  condition:
    any of them
}