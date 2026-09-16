rule TTP_XOR_QUAD_CurrentVersionRun_0f03 {
  strings:
    $key_0f03 = { 5c 6c [2] 78 62 [2] 53 4e [2] 7d 6c [2] 69 77 [2] 66 6d [2] 78 70 [2] 7a 71 [2] 61 77 [2] 7d 70 [2] 61 5f }

  condition:
    any of them
}