rule TTP_XOR_QUAD_CurrentVersionRun_e3da {
  strings:
    $key_e3da = { b0 b5 [2] 94 bb [2] bf 97 [2] 91 b5 [2] 85 ae [2] 8a b4 [2] 94 a9 [2] 96 a8 [2] 8d ae [2] 91 a9 [2] 8d 86 }

  condition:
    any of them
}