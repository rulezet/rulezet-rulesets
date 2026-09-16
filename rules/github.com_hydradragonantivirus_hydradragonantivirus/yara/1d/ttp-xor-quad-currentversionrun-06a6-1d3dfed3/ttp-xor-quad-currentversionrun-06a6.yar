rule TTP_XOR_QUAD_CurrentVersionRun_06a6 {
  strings:
    $key_06a6 = { 55 c9 [2] 71 c7 [2] 5a eb [2] 74 c9 [2] 60 d2 [2] 6f c8 [2] 71 d5 [2] 73 d4 [2] 68 d2 [2] 74 d5 [2] 68 fa }

  condition:
    any of them
}