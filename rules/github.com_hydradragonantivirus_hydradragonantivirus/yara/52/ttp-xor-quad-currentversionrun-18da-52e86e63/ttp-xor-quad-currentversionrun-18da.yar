rule TTP_XOR_QUAD_CurrentVersionRun_18da {
  strings:
    $key_18da = { 4b b5 [2] 6f bb [2] 44 97 [2] 6a b5 [2] 7e ae [2] 71 b4 [2] 6f a9 [2] 6d a8 [2] 76 ae [2] 6a a9 [2] 76 86 }

  condition:
    any of them
}