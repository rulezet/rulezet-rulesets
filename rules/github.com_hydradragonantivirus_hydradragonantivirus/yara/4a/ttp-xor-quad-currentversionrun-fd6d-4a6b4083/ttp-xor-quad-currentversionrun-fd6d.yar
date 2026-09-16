rule TTP_XOR_QUAD_CurrentVersionRun_fd6d {
  strings:
    $key_fd6d = { ae 02 [2] 8a 0c [2] a1 20 [2] 8f 02 [2] 9b 19 [2] 94 03 [2] 8a 1e [2] 88 1f [2] 93 19 [2] 8f 1e [2] 93 31 }

  condition:
    any of them
}