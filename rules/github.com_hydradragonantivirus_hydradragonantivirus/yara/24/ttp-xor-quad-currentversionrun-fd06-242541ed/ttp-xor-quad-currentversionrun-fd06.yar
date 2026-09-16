rule TTP_XOR_QUAD_CurrentVersionRun_fd06 {
  strings:
    $key_fd06 = { ae 69 [2] 8a 67 [2] a1 4b [2] 8f 69 [2] 9b 72 [2] 94 68 [2] 8a 75 [2] 88 74 [2] 93 72 [2] 8f 75 [2] 93 5a }

  condition:
    any of them
}