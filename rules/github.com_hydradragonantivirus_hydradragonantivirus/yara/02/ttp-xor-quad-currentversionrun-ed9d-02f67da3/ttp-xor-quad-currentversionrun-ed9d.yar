rule TTP_XOR_QUAD_CurrentVersionRun_ed9d {
  strings:
    $key_ed9d = { be f2 [2] 9a fc [2] b1 d0 [2] 9f f2 [2] 8b e9 [2] 84 f3 [2] 9a ee [2] 98 ef [2] 83 e9 [2] 9f ee [2] 83 c1 }

  condition:
    any of them
}