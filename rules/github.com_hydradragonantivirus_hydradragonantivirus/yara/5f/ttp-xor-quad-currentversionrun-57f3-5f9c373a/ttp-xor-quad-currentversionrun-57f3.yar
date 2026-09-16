rule TTP_XOR_QUAD_CurrentVersionRun_57f3 {
  strings:
    $key_57f3 = { 04 9c [2] 20 92 [2] 0b be [2] 25 9c [2] 31 87 [2] 3e 9d [2] 20 80 [2] 22 81 [2] 39 87 [2] 25 80 [2] 39 af }

  condition:
    any of them
}