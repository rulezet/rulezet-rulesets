rule TTP_XOR_QUAD_CurrentVersionRun_fd93 {
  strings:
    $key_fd93 = { ae fc [2] 8a f2 [2] a1 de [2] 8f fc [2] 9b e7 [2] 94 fd [2] 8a e0 [2] 88 e1 [2] 93 e7 [2] 8f e0 [2] 93 cf }

  condition:
    any of them
}