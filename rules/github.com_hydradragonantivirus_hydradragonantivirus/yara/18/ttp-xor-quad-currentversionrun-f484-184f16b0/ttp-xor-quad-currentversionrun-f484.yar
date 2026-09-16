rule TTP_XOR_QUAD_CurrentVersionRun_f484 {
  strings:
    $key_f484 = { a7 eb [2] 83 e5 [2] a8 c9 [2] 86 eb [2] 92 f0 [2] 9d ea [2] 83 f7 [2] 81 f6 [2] 9a f0 [2] 86 f7 [2] 9a d8 }

  condition:
    any of them
}