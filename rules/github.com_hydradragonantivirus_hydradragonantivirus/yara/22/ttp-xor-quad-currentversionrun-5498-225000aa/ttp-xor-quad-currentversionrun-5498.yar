rule TTP_XOR_QUAD_CurrentVersionRun_5498 {
  strings:
    $key_5498 = { 07 f7 [2] 23 f9 [2] 08 d5 [2] 26 f7 [2] 32 ec [2] 3d f6 [2] 23 eb [2] 21 ea [2] 3a ec [2] 26 eb [2] 3a c4 }

  condition:
    any of them
}