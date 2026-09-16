rule TTP_XOR_QUAD_CurrentVersionRun_0bda {
  strings:
    $key_0bda = { 58 b5 [2] 7c bb [2] 57 97 [2] 79 b5 [2] 6d ae [2] 62 b4 [2] 7c a9 [2] 7e a8 [2] 65 ae [2] 79 a9 [2] 65 86 }

  condition:
    any of them
}