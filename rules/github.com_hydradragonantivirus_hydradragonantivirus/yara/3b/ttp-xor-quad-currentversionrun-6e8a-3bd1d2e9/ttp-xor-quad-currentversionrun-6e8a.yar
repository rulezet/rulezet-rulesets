rule TTP_XOR_QUAD_CurrentVersionRun_6e8a {
  strings:
    $key_6e8a = { 3d e5 [2] 19 eb [2] 32 c7 [2] 1c e5 [2] 08 fe [2] 07 e4 [2] 19 f9 [2] 1b f8 [2] 00 fe [2] 1c f9 [2] 00 d6 }

  condition:
    any of them
}