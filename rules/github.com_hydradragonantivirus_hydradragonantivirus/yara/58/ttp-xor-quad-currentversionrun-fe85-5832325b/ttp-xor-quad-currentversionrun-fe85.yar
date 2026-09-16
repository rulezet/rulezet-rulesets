rule TTP_XOR_QUAD_CurrentVersionRun_fe85 {
  strings:
    $key_fe85 = { ad ea [2] 89 e4 [2] a2 c8 [2] 8c ea [2] 98 f1 [2] 97 eb [2] 89 f6 [2] 8b f7 [2] 90 f1 [2] 8c f6 [2] 90 d9 }

  condition:
    any of them
}