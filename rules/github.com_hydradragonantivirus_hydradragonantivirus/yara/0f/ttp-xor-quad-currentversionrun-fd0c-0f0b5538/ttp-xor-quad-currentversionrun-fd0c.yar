rule TTP_XOR_QUAD_CurrentVersionRun_fd0c {
  strings:
    $key_fd0c = { ae 63 [2] 8a 6d [2] a1 41 [2] 8f 63 [2] 9b 78 [2] 94 62 [2] 8a 7f [2] 88 7e [2] 93 78 [2] 8f 7f [2] 93 50 }

  condition:
    any of them
}