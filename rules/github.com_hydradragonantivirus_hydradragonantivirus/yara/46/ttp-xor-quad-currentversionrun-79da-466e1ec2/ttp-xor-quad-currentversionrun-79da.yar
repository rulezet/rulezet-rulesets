rule TTP_XOR_QUAD_CurrentVersionRun_79da {
  strings:
    $key_79da = { 2a b5 [2] 0e bb [2] 25 97 [2] 0b b5 [2] 1f ae [2] 10 b4 [2] 0e a9 [2] 0c a8 [2] 17 ae [2] 0b a9 [2] 17 86 }

  condition:
    any of them
}