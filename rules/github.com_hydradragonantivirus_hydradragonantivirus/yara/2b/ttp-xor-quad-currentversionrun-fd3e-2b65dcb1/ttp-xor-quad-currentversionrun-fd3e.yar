rule TTP_XOR_QUAD_CurrentVersionRun_fd3e {
  strings:
    $key_fd3e = { ae 51 [2] 8a 5f [2] a1 73 [2] 8f 51 [2] 9b 4a [2] 94 50 [2] 8a 4d [2] 88 4c [2] 93 4a [2] 8f 4d [2] 93 62 }

  condition:
    any of them
}