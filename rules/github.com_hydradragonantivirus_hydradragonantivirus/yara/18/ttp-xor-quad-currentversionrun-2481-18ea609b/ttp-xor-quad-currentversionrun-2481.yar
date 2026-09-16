rule TTP_XOR_QUAD_CurrentVersionRun_2481 {
  strings:
    $key_2481 = { 77 ee [2] 53 e0 [2] 78 cc [2] 56 ee [2] 42 f5 [2] 4d ef [2] 53 f2 [2] 51 f3 [2] 4a f5 [2] 56 f2 [2] 4a dd }

  condition:
    any of them
}