rule TTP_XOR_QUAD_CurrentVersionRun_fd10 {
  strings:
    $key_fd10 = { ae 7f [2] 8a 71 [2] a1 5d [2] 8f 7f [2] 9b 64 [2] 94 7e [2] 8a 63 [2] 88 62 [2] 93 64 [2] 8f 63 [2] 93 4c }

  condition:
    any of them
}