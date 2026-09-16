rule TTP_XOR_QUAD_CurrentVersionRun_fd3c {
  strings:
    $key_fd3c = { ae 53 [2] 8a 5d [2] a1 71 [2] 8f 53 [2] 9b 48 [2] 94 52 [2] 8a 4f [2] 88 4e [2] 93 48 [2] 8f 4f [2] 93 60 }

  condition:
    any of them
}