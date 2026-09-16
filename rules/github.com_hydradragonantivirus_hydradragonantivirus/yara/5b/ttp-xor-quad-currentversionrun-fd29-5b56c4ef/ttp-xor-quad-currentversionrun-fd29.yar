rule TTP_XOR_QUAD_CurrentVersionRun_fd29 {
  strings:
    $key_fd29 = { ae 46 [2] 8a 48 [2] a1 64 [2] 8f 46 [2] 9b 5d [2] 94 47 [2] 8a 5a [2] 88 5b [2] 93 5d [2] 8f 5a [2] 93 75 }

  condition:
    any of them
}