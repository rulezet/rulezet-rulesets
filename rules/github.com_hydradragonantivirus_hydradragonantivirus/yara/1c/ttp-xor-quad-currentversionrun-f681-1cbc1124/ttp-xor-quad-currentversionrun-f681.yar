rule TTP_XOR_QUAD_CurrentVersionRun_f681 {
  strings:
    $key_f681 = { a5 ee [2] 81 e0 [2] aa cc [2] 84 ee [2] 90 f5 [2] 9f ef [2] 81 f2 [2] 83 f3 [2] 98 f5 [2] 84 f2 [2] 98 dd }

  condition:
    any of them
}