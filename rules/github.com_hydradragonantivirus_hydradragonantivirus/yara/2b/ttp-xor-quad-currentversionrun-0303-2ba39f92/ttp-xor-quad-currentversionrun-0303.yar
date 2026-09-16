rule TTP_XOR_QUAD_CurrentVersionRun_0303 {
  strings:
    $key_0303 = { 50 6c [2] 74 62 [2] 5f 4e [2] 71 6c [2] 65 77 [2] 6a 6d [2] 74 70 [2] 76 71 [2] 6d 77 [2] 71 70 [2] 6d 5f }

  condition:
    any of them
}