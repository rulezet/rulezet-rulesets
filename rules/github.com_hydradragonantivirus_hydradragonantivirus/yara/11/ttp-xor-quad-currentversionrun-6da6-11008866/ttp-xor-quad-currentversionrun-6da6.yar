rule TTP_XOR_QUAD_CurrentVersionRun_6da6 {
  strings:
    $key_6da6 = { 3e c9 [2] 1a c7 [2] 31 eb [2] 1f c9 [2] 0b d2 [2] 04 c8 [2] 1a d5 [2] 18 d4 [2] 03 d2 [2] 1f d5 [2] 03 fa }

  condition:
    any of them
}