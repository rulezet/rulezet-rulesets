rule TTP_XOR_QUAD_CurrentVersionRun_3f98 {
  strings:
    $key_3f98 = { 6c f7 [2] 48 f9 [2] 63 d5 [2] 4d f7 [2] 59 ec [2] 56 f6 [2] 48 eb [2] 4a ea [2] 51 ec [2] 4d eb [2] 51 c4 }

  condition:
    any of them
}