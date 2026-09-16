rule TTP_XOR_QUAD_CurrentVersionRun_2703 {
  strings:
    $key_2703 = { 74 6c [2] 50 62 [2] 7b 4e [2] 55 6c [2] 41 77 [2] 4e 6d [2] 50 70 [2] 52 71 [2] 49 77 [2] 55 70 [2] 49 5f }

  condition:
    any of them
}