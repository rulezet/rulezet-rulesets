rule TTP_XOR_QUAD_CurrentVersionRun_fe98 {
  strings:
    $key_fe98 = { ad f7 [2] 89 f9 [2] a2 d5 [2] 8c f7 [2] 98 ec [2] 97 f6 [2] 89 eb [2] 8b ea [2] 90 ec [2] 8c eb [2] 90 c4 }

  condition:
    any of them
}