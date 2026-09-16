rule TTP_XOR_QUAD_CurrentVersionRun_5495 {
  strings:
    $key_5495 = { 07 fa [2] 23 f4 [2] 08 d8 [2] 26 fa [2] 32 e1 [2] 3d fb [2] 23 e6 [2] 21 e7 [2] 3a e1 [2] 26 e6 [2] 3a c9 }

  condition:
    any of them
}