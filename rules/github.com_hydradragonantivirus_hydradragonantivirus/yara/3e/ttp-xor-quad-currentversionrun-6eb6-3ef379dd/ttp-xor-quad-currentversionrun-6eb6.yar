rule TTP_XOR_QUAD_CurrentVersionRun_6eb6 {
  strings:
    $key_6eb6 = { 3d d9 [2] 19 d7 [2] 32 fb [2] 1c d9 [2] 08 c2 [2] 07 d8 [2] 19 c5 [2] 1b c4 [2] 00 c2 [2] 1c c5 [2] 00 ea }

  condition:
    any of them
}