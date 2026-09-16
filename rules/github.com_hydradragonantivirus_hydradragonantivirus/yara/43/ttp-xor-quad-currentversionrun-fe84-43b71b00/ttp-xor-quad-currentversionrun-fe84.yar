rule TTP_XOR_QUAD_CurrentVersionRun_fe84 {
  strings:
    $key_fe84 = { ad eb [2] 89 e5 [2] a2 c9 [2] 8c eb [2] 98 f0 [2] 97 ea [2] 89 f7 [2] 8b f6 [2] 90 f0 [2] 8c f7 [2] 90 d8 }

  condition:
    any of them
}