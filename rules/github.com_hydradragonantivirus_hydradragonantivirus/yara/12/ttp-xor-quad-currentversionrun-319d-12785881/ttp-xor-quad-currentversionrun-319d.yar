rule TTP_XOR_QUAD_CurrentVersionRun_319d {
  strings:
    $key_319d = { 62 f2 [2] 46 fc [2] 6d d0 [2] 43 f2 [2] 57 e9 [2] 58 f3 [2] 46 ee [2] 44 ef [2] 5f e9 [2] 43 ee [2] 5f c1 }

  condition:
    any of them
}