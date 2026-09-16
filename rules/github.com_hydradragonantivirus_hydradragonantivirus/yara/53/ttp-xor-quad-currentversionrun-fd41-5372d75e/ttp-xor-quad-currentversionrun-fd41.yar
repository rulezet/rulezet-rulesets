rule TTP_XOR_QUAD_CurrentVersionRun_fd41 {
  strings:
    $key_fd41 = { ae 2e [2] 8a 20 [2] a1 0c [2] 8f 2e [2] 9b 35 [2] 94 2f [2] 8a 32 [2] 88 33 [2] 93 35 [2] 8f 32 [2] 93 1d }

  condition:
    any of them
}