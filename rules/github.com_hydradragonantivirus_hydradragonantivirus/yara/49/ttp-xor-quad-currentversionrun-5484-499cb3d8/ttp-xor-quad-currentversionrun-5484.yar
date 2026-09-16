rule TTP_XOR_QUAD_CurrentVersionRun_5484 {
  strings:
    $key_5484 = { 07 eb [2] 23 e5 [2] 08 c9 [2] 26 eb [2] 32 f0 [2] 3d ea [2] 23 f7 [2] 21 f6 [2] 3a f0 [2] 26 f7 [2] 3a d8 }

  condition:
    any of them
}