rule TTP_XOR_QUAD_CurrentVersionRun_fd2a {
  strings:
    $key_fd2a = { ae 45 [2] 8a 4b [2] a1 67 [2] 8f 45 [2] 9b 5e [2] 94 44 [2] 8a 59 [2] 88 58 [2] 93 5e [2] 8f 59 [2] 93 76 }

  condition:
    any of them
}