rule TTP_XOR_QUAD_CurrentVersionRun_2b73 {
  strings:
    $key_2b73 = { 78 1c [2] 5c 12 [2] 77 3e [2] 59 1c [2] 4d 07 [2] 42 1d [2] 5c 00 [2] 5e 01 [2] 45 07 [2] 59 00 [2] 45 2f }

  condition:
    any of them
}