rule TTP_XOR_QUAD_CurrentVersionRun_0e81 {
  strings:
    $key_0e81 = { 5d ee [2] 79 e0 [2] 52 cc [2] 7c ee [2] 68 f5 [2] 67 ef [2] 79 f2 [2] 7b f3 [2] 60 f5 [2] 7c f2 [2] 60 dd }

  condition:
    any of them
}