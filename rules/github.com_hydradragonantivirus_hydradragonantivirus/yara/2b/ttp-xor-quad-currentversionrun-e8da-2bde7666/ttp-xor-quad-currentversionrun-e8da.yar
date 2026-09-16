rule TTP_XOR_QUAD_CurrentVersionRun_e8da {
  strings:
    $key_e8da = { bb b5 [2] 9f bb [2] b4 97 [2] 9a b5 [2] 8e ae [2] 81 b4 [2] 9f a9 [2] 9d a8 [2] 86 ae [2] 9a a9 [2] 86 86 }

  condition:
    any of them
}