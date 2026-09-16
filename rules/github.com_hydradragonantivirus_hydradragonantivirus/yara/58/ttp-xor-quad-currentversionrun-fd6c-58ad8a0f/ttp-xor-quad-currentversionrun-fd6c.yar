rule TTP_XOR_QUAD_CurrentVersionRun_fd6c {
  strings:
    $key_fd6c = { ae 03 [2] 8a 0d [2] a1 21 [2] 8f 03 [2] 9b 18 [2] 94 02 [2] 8a 1f [2] 88 1e [2] 93 18 [2] 8f 1f [2] 93 30 }

  condition:
    any of them
}