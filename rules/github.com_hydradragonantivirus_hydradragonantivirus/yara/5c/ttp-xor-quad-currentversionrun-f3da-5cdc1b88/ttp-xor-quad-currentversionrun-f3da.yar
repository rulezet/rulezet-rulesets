rule TTP_XOR_QUAD_CurrentVersionRun_f3da {
  strings:
    $key_f3da = { a0 b5 [2] 84 bb [2] af 97 [2] 81 b5 [2] 95 ae [2] 9a b4 [2] 84 a9 [2] 86 a8 [2] 9d ae [2] 81 a9 [2] 9d 86 }

  condition:
    any of them
}