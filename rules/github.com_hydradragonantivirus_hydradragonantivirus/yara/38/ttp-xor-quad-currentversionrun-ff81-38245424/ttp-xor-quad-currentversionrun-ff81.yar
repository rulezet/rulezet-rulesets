rule TTP_XOR_QUAD_CurrentVersionRun_ff81 {
  strings:
    $key_ff81 = { ac ee [2] 88 e0 [2] a3 cc [2] 8d ee [2] 99 f5 [2] 96 ef [2] 88 f2 [2] 8a f3 [2] 91 f5 [2] 8d f2 [2] 91 dd }

  condition:
    any of them
}