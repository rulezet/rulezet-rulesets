rule TTP_XOR_QUAD_CurrentVersionRun_fd0e {
  strings:
    $key_fd0e = { ae 61 [2] 8a 6f [2] a1 43 [2] 8f 61 [2] 9b 7a [2] 94 60 [2] 8a 7d [2] 88 7c [2] 93 7a [2] 8f 7d [2] 93 52 }

  condition:
    any of them
}