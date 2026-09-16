rule TTP_XOR_QUAD_CurrentVersionRun_fd14 {
  strings:
    $key_fd14 = { ae 7b [2] 8a 75 [2] a1 59 [2] 8f 7b [2] 9b 60 [2] 94 7a [2] 8a 67 [2] 88 66 [2] 93 60 [2] 8f 67 [2] 93 48 }

  condition:
    any of them
}