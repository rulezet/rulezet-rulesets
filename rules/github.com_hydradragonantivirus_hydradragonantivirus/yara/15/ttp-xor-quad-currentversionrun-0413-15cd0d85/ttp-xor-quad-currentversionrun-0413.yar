rule TTP_XOR_QUAD_CurrentVersionRun_0413 {
  strings:
    $key_0413 = { 57 7c [2] 73 72 [2] 58 5e [2] 76 7c [2] 62 67 [2] 6d 7d [2] 73 60 [2] 71 61 [2] 6a 67 [2] 76 60 [2] 6a 4f }

  condition:
    any of them
}