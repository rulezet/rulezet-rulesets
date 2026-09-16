rule TTP_XOR_QUAD_CurrentVersionRun_2cf3 {
  strings:
    $key_2cf3 = { 7f 9c [2] 5b 92 [2] 70 be [2] 5e 9c [2] 4a 87 [2] 45 9d [2] 5b 80 [2] 59 81 [2] 42 87 [2] 5e 80 [2] 42 af }

  condition:
    any of them
}