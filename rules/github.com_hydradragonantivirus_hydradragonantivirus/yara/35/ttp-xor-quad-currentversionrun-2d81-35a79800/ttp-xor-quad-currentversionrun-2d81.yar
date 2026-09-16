rule TTP_XOR_QUAD_CurrentVersionRun_2d81 {
  strings:
    $key_2d81 = { 7e ee [2] 5a e0 [2] 71 cc [2] 5f ee [2] 4b f5 [2] 44 ef [2] 5a f2 [2] 58 f3 [2] 43 f5 [2] 5f f2 [2] 43 dd }

  condition:
    any of them
}