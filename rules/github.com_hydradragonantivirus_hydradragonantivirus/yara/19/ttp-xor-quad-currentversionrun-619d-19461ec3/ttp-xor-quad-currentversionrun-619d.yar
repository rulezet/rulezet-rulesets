rule TTP_XOR_QUAD_CurrentVersionRun_619d {
  strings:
    $key_619d = { 32 f2 [2] 16 fc [2] 3d d0 [2] 13 f2 [2] 07 e9 [2] 08 f3 [2] 16 ee [2] 14 ef [2] 0f e9 [2] 13 ee [2] 0f c1 }

  condition:
    any of them
}