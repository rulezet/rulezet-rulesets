rule TTP_XOR_QUAD_CurrentVersionRun_f581 {
  strings:
    $key_f581 = { a6 ee [2] 82 e0 [2] a9 cc [2] 87 ee [2] 93 f5 [2] 9c ef [2] 82 f2 [2] 80 f3 [2] 9b f5 [2] 87 f2 [2] 9b dd }

  condition:
    any of them
}