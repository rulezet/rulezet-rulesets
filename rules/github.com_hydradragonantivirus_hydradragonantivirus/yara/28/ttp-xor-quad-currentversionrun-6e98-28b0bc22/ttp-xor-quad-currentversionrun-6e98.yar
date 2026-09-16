rule TTP_XOR_QUAD_CurrentVersionRun_6e98 {
  strings:
    $key_6e98 = { 3d f7 [2] 19 f9 [2] 32 d5 [2] 1c f7 [2] 08 ec [2] 07 f6 [2] 19 eb [2] 1b ea [2] 00 ec [2] 1c eb [2] 00 c4 }

  condition:
    any of them
}