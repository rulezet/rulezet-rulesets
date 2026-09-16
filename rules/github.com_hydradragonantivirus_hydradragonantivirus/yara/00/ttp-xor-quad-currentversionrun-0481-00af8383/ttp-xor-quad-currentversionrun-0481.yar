rule TTP_XOR_QUAD_CurrentVersionRun_0481 {
  strings:
    $key_0481 = { 57 ee [2] 73 e0 [2] 58 cc [2] 76 ee [2] 62 f5 [2] 6d ef [2] 73 f2 [2] 71 f3 [2] 6a f5 [2] 76 f2 [2] 6a dd }

  condition:
    any of them
}