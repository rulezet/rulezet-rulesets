rule TTP_XOR_QUAD_CurrentVersionRun_619c {
  strings:
    $key_619c = { 32 f3 [2] 16 fd [2] 3d d1 [2] 13 f3 [2] 07 e8 [2] 08 f2 [2] 16 ef [2] 14 ee [2] 0f e8 [2] 13 ef [2] 0f c0 }

  condition:
    any of them
}