rule TTP_XOR_QUAD_CurrentVersionRun_fd96 {
  strings:
    $key_fd96 = { ae f9 [2] 8a f7 [2] a1 db [2] 8f f9 [2] 9b e2 [2] 94 f8 [2] 8a e5 [2] 88 e4 [2] 93 e2 [2] 8f e5 [2] 93 ca }

  condition:
    any of them
}