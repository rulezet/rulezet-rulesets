rule TTP_XOR_QUAD_CurrentVersionRun_1f13 {
  strings:
    $key_1f13 = { 4c 7c [2] 68 72 [2] 43 5e [2] 6d 7c [2] 79 67 [2] 76 7d [2] 68 60 [2] 6a 61 [2] 71 67 [2] 6d 60 [2] 71 4f }

  condition:
    any of them
}