rule TTP_XOR_QUAD_CurrentVersionRun_6181 {
  strings:
    $key_6181 = { 32 ee [2] 16 e0 [2] 3d cc [2] 13 ee [2] 07 f5 [2] 08 ef [2] 16 f2 [2] 14 f3 [2] 0f f5 [2] 13 f2 [2] 0f dd }

  condition:
    any of them
}