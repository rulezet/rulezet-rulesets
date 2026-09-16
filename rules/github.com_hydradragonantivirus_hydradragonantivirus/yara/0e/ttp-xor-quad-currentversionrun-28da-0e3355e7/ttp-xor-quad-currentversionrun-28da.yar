rule TTP_XOR_QUAD_CurrentVersionRun_28da {
  strings:
    $key_28da = { 7b b5 [2] 5f bb [2] 74 97 [2] 5a b5 [2] 4e ae [2] 41 b4 [2] 5f a9 [2] 5d a8 [2] 46 ae [2] 5a a9 [2] 46 86 }

  condition:
    any of them
}