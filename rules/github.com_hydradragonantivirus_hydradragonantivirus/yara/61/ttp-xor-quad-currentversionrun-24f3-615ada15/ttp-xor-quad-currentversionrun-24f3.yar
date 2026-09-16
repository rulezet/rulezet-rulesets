rule TTP_XOR_QUAD_CurrentVersionRun_24f3 {
  strings:
    $key_24f3 = { 77 9c [2] 53 92 [2] 78 be [2] 56 9c [2] 42 87 [2] 4d 9d [2] 53 80 [2] 51 81 [2] 4a 87 [2] 56 80 [2] 4a af }

  condition:
    any of them
}