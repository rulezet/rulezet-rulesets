rule TTP_XOR_QUAD_CurrentVersionRun_1bda {
  strings:
    $key_1bda = { 48 b5 [2] 6c bb [2] 47 97 [2] 69 b5 [2] 7d ae [2] 72 b4 [2] 6c a9 [2] 6e a8 [2] 75 ae [2] 69 a9 [2] 75 86 }

  condition:
    any of them
}