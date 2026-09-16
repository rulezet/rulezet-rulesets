rule TTP_XOR_QUAD_CurrentVersionRun_1a23 {
  strings:
    $key_1a23 = { 49 4c [2] 6d 42 [2] 46 6e [2] 68 4c [2] 7c 57 [2] 73 4d [2] 6d 50 [2] 6f 51 [2] 74 57 [2] 68 50 [2] 74 7f }

  condition:
    any of them
}