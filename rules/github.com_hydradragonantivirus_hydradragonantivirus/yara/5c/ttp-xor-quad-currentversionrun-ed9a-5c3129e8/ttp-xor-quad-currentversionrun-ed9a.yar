rule TTP_XOR_QUAD_CurrentVersionRun_ed9a {
  strings:
    $key_ed9a = { be f5 [2] 9a fb [2] b1 d7 [2] 9f f5 [2] 8b ee [2] 84 f4 [2] 9a e9 [2] 98 e8 [2] 83 ee [2] 9f e9 [2] 83 c6 }

  condition:
    any of them
}