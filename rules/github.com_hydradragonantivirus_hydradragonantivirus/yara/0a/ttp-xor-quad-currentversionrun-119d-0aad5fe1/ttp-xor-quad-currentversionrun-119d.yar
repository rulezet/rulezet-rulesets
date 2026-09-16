rule TTP_XOR_QUAD_CurrentVersionRun_119d {
  strings:
    $key_119d = { 42 f2 [2] 66 fc [2] 4d d0 [2] 63 f2 [2] 77 e9 [2] 78 f3 [2] 66 ee [2] 64 ef [2] 7f e9 [2] 63 ee [2] 7f c1 }

  condition:
    any of them
}