rule TTP_XOR_QUAD_CurrentVersionRun_6198 {
  strings:
    $key_6198 = { 32 f7 [2] 16 f9 [2] 3d d5 [2] 13 f7 [2] 07 ec [2] 08 f6 [2] 16 eb [2] 14 ea [2] 0f ec [2] 13 eb [2] 0f c4 }

  condition:
    any of them
}