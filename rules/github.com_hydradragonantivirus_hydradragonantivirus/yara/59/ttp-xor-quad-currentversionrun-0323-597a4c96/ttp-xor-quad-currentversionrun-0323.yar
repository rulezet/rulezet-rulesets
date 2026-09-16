rule TTP_XOR_QUAD_CurrentVersionRun_0323 {
  strings:
    $key_0323 = { 50 4c [2] 74 42 [2] 5f 6e [2] 71 4c [2] 65 57 [2] 6a 4d [2] 74 50 [2] 76 51 [2] 6d 57 [2] 71 50 [2] 6d 7f }

  condition:
    any of them
}