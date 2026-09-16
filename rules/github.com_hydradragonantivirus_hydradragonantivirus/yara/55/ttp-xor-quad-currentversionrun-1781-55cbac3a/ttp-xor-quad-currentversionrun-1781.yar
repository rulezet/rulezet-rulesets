rule TTP_XOR_QUAD_CurrentVersionRun_1781 {
  strings:
    $key_1781 = { 44 ee [2] 60 e0 [2] 4b cc [2] 65 ee [2] 71 f5 [2] 7e ef [2] 60 f2 [2] 62 f3 [2] 79 f5 [2] 65 f2 [2] 79 dd }

  condition:
    any of them
}