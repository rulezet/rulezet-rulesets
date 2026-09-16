rule TTP_XOR_QUAD_CurrentVersionRun_ed9c {
  strings:
    $key_ed9c = { be f3 [2] 9a fd [2] b1 d1 [2] 9f f3 [2] 8b e8 [2] 84 f2 [2] 9a ef [2] 98 ee [2] 83 e8 [2] 9f ef [2] 83 c0 }

  condition:
    any of them
}