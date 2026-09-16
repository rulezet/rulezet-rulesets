rule TTP_XOR_QUAD_CurrentVersionRun_35f3 {
  strings:
    $key_35f3 = { 66 9c [2] 42 92 [2] 69 be [2] 47 9c [2] 53 87 [2] 5c 9d [2] 42 80 [2] 40 81 [2] 5b 87 [2] 47 80 [2] 5b af }

  condition:
    any of them
}