rule TTP_XOR_QUAD_CurrentVersionRun_7581 {
  strings:
    $key_7581 = { 26 ee [2] 02 e0 [2] 29 cc [2] 07 ee [2] 13 f5 [2] 1c ef [2] 02 f2 [2] 00 f3 [2] 1b f5 [2] 07 f2 [2] 1b dd }

  condition:
    any of them
}