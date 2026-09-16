rule TTP_XOR_QUAD_CurrentVersionRun_fd9d {
  strings:
    $key_fd9d = { ae f2 [2] 8a fc [2] a1 d0 [2] 8f f2 [2] 9b e9 [2] 94 f3 [2] 8a ee [2] 88 ef [2] 93 e9 [2] 8f ee [2] 93 c1 }

  condition:
    any of them
}