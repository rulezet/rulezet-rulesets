rule TTP_XOR_QUAD_CurrentVersionRun_2203 {
  strings:
    $key_2203 = { 71 6c [2] 55 62 [2] 7e 4e [2] 50 6c [2] 44 77 [2] 4b 6d [2] 55 70 [2] 57 71 [2] 4c 77 [2] 50 70 [2] 4c 5f }

  condition:
    any of them
}