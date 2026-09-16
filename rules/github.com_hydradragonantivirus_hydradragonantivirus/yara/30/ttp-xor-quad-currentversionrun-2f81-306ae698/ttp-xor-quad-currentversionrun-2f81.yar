rule TTP_XOR_QUAD_CurrentVersionRun_2f81 {
  strings:
    $key_2f81 = { 7c ee [2] 58 e0 [2] 73 cc [2] 5d ee [2] 49 f5 [2] 46 ef [2] 58 f2 [2] 5a f3 [2] 41 f5 [2] 5d f2 [2] 41 dd }

  condition:
    any of them
}