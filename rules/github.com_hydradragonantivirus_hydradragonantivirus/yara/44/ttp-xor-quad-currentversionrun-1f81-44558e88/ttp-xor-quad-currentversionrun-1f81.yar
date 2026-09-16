rule TTP_XOR_QUAD_CurrentVersionRun_1f81 {
  strings:
    $key_1f81 = { 4c ee [2] 68 e0 [2] 43 cc [2] 6d ee [2] 79 f5 [2] 76 ef [2] 68 f2 [2] 6a f3 [2] 71 f5 [2] 6d f2 [2] 71 dd }

  condition:
    any of them
}