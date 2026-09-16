rule TTP_XOR_QUAD_CurrentVersionRun_2b03 {
  strings:
    $key_2b03 = { 78 6c [2] 5c 62 [2] 77 4e [2] 59 6c [2] 4d 77 [2] 42 6d [2] 5c 70 [2] 5e 71 [2] 45 77 [2] 59 70 [2] 45 5f }

  condition:
    any of them
}