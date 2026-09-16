rule TTP_XOR_QUAD_CurrentVersionRun_6ead {
  strings:
    $key_6ead = { 3d c2 [2] 19 cc [2] 32 e0 [2] 1c c2 [2] 08 d9 [2] 07 c3 [2] 19 de [2] 1b df [2] 00 d9 [2] 1c de [2] 00 f1 }

  condition:
    any of them
}