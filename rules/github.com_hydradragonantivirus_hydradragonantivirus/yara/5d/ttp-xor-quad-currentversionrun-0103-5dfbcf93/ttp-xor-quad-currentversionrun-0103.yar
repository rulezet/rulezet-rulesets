rule TTP_XOR_QUAD_CurrentVersionRun_0103 {
  strings:
    $key_0103 = { 52 6c [2] 76 62 [2] 5d 4e [2] 73 6c [2] 67 77 [2] 68 6d [2] 76 70 [2] 74 71 [2] 6f 77 [2] 73 70 [2] 6f 5f }

  condition:
    any of them
}