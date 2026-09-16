rule TTP_XOR_QUAD_CurrentVersionRun_fd3f {
  strings:
    $key_fd3f = { ae 50 [2] 8a 5e [2] a1 72 [2] 8f 50 [2] 9b 4b [2] 94 51 [2] 8a 4c [2] 88 4d [2] 93 4b [2] 8f 4c [2] 93 63 }

  condition:
    any of them
}