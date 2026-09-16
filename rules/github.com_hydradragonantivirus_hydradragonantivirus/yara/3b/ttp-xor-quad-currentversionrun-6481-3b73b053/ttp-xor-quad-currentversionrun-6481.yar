rule TTP_XOR_QUAD_CurrentVersionRun_6481 {
  strings:
    $key_6481 = { 37 ee [2] 13 e0 [2] 38 cc [2] 16 ee [2] 02 f5 [2] 0d ef [2] 13 f2 [2] 11 f3 [2] 0a f5 [2] 16 f2 [2] 0a dd }

  condition:
    any of them
}