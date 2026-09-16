rule TTP_XOR_QUAD_CurrentVersionRun_fd91 {
  strings:
    $key_fd91 = { ae fe [2] 8a f0 [2] a1 dc [2] 8f fe [2] 9b e5 [2] 94 ff [2] 8a e2 [2] 88 e3 [2] 93 e5 [2] 8f e2 [2] 93 cd }

  condition:
    any of them
}