rule TTP_XOR_QUAD_CurrentVersionRun_2bf3 {
  strings:
    $key_2bf3 = { 78 9c [2] 5c 92 [2] 77 be [2] 59 9c [2] 4d 87 [2] 42 9d [2] 5c 80 [2] 5e 81 [2] 45 87 [2] 59 80 [2] 45 af }

  condition:
    any of them
}