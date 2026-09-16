rule TTP_XOR_QUAD_CurrentVersionRun_fd40 {
  strings:
    $key_fd40 = { ae 2f [2] 8a 21 [2] a1 0d [2] 8f 2f [2] 9b 34 [2] 94 2e [2] 8a 33 [2] 88 32 [2] 93 34 [2] 8f 33 [2] 93 1c }

  condition:
    any of them
}