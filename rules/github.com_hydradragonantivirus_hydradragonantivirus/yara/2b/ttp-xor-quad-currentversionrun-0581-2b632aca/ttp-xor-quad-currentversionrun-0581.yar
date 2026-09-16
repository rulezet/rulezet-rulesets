rule TTP_XOR_QUAD_CurrentVersionRun_0581 {
  strings:
    $key_0581 = { 56 ee [2] 72 e0 [2] 59 cc [2] 77 ee [2] 63 f5 [2] 6c ef [2] 72 f2 [2] 70 f3 [2] 6b f5 [2] 77 f2 [2] 6b dd }

  condition:
    any of them
}