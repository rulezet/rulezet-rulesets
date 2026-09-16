rule TTP_XOR_QUAD_CurrentVersionRun_fd2c {
  strings:
    $key_fd2c = { ae 43 [2] 8a 4d [2] a1 61 [2] 8f 43 [2] 9b 58 [2] 94 42 [2] 8a 5f [2] 88 5e [2] 93 58 [2] 8f 5f [2] 93 70 }

  condition:
    any of them
}