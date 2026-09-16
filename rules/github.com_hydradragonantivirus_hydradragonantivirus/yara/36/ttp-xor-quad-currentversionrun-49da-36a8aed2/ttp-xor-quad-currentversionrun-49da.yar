rule TTP_XOR_QUAD_CurrentVersionRun_49da {
  strings:
    $key_49da = { 1a b5 [2] 3e bb [2] 15 97 [2] 3b b5 [2] 2f ae [2] 20 b4 [2] 3e a9 [2] 3c a8 [2] 27 ae [2] 3b a9 [2] 27 86 }

  condition:
    any of them
}