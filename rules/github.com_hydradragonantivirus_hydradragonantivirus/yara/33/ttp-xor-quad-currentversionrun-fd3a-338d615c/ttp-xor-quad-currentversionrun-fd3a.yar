rule TTP_XOR_QUAD_CurrentVersionRun_fd3a {
  strings:
    $key_fd3a = { ae 55 [2] 8a 5b [2] a1 77 [2] 8f 55 [2] 9b 4e [2] 94 54 [2] 8a 49 [2] 88 48 [2] 93 4e [2] 8f 49 [2] 93 66 }

  condition:
    any of them
}