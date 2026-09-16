rule TTP_XOR_QUAD_CurrentVersionRun_0f81 {
  strings:
    $key_0f81 = { 5c ee [2] 78 e0 [2] 53 cc [2] 7d ee [2] 69 f5 [2] 66 ef [2] 78 f2 [2] 7a f3 [2] 61 f5 [2] 7d f2 [2] 61 dd }

  condition:
    any of them
}