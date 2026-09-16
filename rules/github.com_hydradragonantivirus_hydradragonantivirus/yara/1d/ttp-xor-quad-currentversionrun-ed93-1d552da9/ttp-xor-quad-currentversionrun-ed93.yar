rule TTP_XOR_QUAD_CurrentVersionRun_ed93 {
  strings:
    $key_ed93 = { be fc [2] 9a f2 [2] b1 de [2] 9f fc [2] 8b e7 [2] 84 fd [2] 9a e0 [2] 98 e1 [2] 83 e7 [2] 9f e0 [2] 83 cf }

  condition:
    any of them
}