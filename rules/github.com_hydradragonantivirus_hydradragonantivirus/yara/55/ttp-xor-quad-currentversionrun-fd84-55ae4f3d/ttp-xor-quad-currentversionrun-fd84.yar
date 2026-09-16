rule TTP_XOR_QUAD_CurrentVersionRun_fd84 {
  strings:
    $key_fd84 = { ae eb [2] 8a e5 [2] a1 c9 [2] 8f eb [2] 9b f0 [2] 94 ea [2] 8a f7 [2] 88 f6 [2] 93 f0 [2] 8f f7 [2] 93 d8 }

  condition:
    any of them
}