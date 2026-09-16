rule TTP_XOR_QUAD_CurrentVersionRun_26a6 {
  strings:
    $key_26a6 = { 75 c9 [2] 51 c7 [2] 7a eb [2] 54 c9 [2] 40 d2 [2] 4f c8 [2] 51 d5 [2] 53 d4 [2] 48 d2 [2] 54 d5 [2] 48 fa }

  condition:
    any of them
}