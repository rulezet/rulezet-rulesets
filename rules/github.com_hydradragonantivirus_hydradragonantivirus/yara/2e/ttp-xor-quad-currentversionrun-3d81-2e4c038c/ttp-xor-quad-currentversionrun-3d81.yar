rule TTP_XOR_QUAD_CurrentVersionRun_3d81 {
  strings:
    $key_3d81 = { 6e ee [2] 4a e0 [2] 61 cc [2] 4f ee [2] 5b f5 [2] 54 ef [2] 4a f2 [2] 48 f3 [2] 53 f5 [2] 4f f2 [2] 53 dd }

  condition:
    any of them
}