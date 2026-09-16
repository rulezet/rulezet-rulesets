rule TTP_XOR_QUAD_CurrentVersionRun_2b63 {
  strings:
    $key_2b63 = { 78 0c [2] 5c 02 [2] 77 2e [2] 59 0c [2] 4d 17 [2] 42 0d [2] 5c 10 [2] 5e 11 [2] 45 17 [2] 59 10 [2] 45 3f }

  condition:
    any of them
}