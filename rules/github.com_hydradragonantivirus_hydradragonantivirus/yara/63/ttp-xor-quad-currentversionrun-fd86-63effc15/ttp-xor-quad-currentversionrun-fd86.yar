rule TTP_XOR_QUAD_CurrentVersionRun_fd86 {
  strings:
    $key_fd86 = { ae e9 [2] 8a e7 [2] a1 cb [2] 8f e9 [2] 9b f2 [2] 94 e8 [2] 8a f5 [2] 88 f4 [2] 93 f2 [2] 8f f5 [2] 93 da }

  condition:
    any of them
}