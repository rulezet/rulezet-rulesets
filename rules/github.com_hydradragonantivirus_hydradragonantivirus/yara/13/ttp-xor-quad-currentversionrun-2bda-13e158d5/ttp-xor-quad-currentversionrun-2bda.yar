rule TTP_XOR_QUAD_CurrentVersionRun_2bda {
  strings:
    $key_2bda = { 78 b5 [2] 5c bb [2] 77 97 [2] 59 b5 [2] 4d ae [2] 42 b4 [2] 5c a9 [2] 5e a8 [2] 45 ae [2] 59 a9 [2] 45 86 }

  condition:
    any of them
}