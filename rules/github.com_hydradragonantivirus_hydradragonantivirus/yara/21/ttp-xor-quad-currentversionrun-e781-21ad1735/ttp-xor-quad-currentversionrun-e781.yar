rule TTP_XOR_QUAD_CurrentVersionRun_e781 {
  strings:
    $key_e781 = { b4 ee [2] 90 e0 [2] bb cc [2] 95 ee [2] 81 f5 [2] 8e ef [2] 90 f2 [2] 92 f3 [2] 89 f5 [2] 95 f2 [2] 89 dd }

  condition:
    any of them
}