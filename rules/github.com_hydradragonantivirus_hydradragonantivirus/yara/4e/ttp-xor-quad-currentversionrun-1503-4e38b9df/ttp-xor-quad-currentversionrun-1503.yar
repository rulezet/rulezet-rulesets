rule TTP_XOR_QUAD_CurrentVersionRun_1503 {
  strings:
    $key_1503 = { 46 6c [2] 62 62 [2] 49 4e [2] 67 6c [2] 73 77 [2] 7c 6d [2] 62 70 [2] 60 71 [2] 7b 77 [2] 67 70 [2] 7b 5f }

  condition:
    any of them
}