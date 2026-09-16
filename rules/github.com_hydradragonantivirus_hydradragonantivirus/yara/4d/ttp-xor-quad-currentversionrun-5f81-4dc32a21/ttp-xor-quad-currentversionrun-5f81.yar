rule TTP_XOR_QUAD_CurrentVersionRun_5f81 {
  strings:
    $key_5f81 = { 0c ee [2] 28 e0 [2] 03 cc [2] 2d ee [2] 39 f5 [2] 36 ef [2] 28 f2 [2] 2a f3 [2] 31 f5 [2] 2d f2 [2] 31 dd }

  condition:
    any of them
}