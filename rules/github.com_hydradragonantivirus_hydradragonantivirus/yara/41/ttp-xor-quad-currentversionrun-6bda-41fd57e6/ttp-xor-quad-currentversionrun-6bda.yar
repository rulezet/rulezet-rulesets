rule TTP_XOR_QUAD_CurrentVersionRun_6bda {
  strings:
    $key_6bda = { 38 b5 [2] 1c bb [2] 37 97 [2] 19 b5 [2] 0d ae [2] 02 b4 [2] 1c a9 [2] 1e a8 [2] 05 ae [2] 19 a9 [2] 05 86 }

  condition:
    any of them
}