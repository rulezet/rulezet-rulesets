rule TTP_XOR_QUAD_CurrentVersionRun_fd21 {
  strings:
    $key_fd21 = { ae 4e [2] 8a 40 [2] a1 6c [2] 8f 4e [2] 9b 55 [2] 94 4f [2] 8a 52 [2] 88 53 [2] 93 55 [2] 8f 52 [2] 93 7d }

  condition:
    any of them
}