rule TTP_XOR_QUAD_CurrentVersionRun_e481 {
  strings:
    $key_e481 = { b7 ee [2] 93 e0 [2] b8 cc [2] 96 ee [2] 82 f5 [2] 8d ef [2] 93 f2 [2] 91 f3 [2] 8a f5 [2] 96 f2 [2] 8a dd }

  condition:
    any of them
}