rule TTP_XOR_QUAD_CurrentVersionRun_3481 {
  strings:
    $key_3481 = { 67 ee [2] 43 e0 [2] 68 cc [2] 46 ee [2] 52 f5 [2] 5d ef [2] 43 f2 [2] 41 f3 [2] 5a f5 [2] 46 f2 [2] 5a dd }

  condition:
    any of them
}