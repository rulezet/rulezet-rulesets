rule TTP_XOR_QUAD_CurrentVersionRun_fd3b {
  strings:
    $key_fd3b = { ae 54 [2] 8a 5a [2] a1 76 [2] 8f 54 [2] 9b 4f [2] 94 55 [2] 8a 48 [2] 88 49 [2] 93 4f [2] 8f 48 [2] 93 67 }

  condition:
    any of them
}