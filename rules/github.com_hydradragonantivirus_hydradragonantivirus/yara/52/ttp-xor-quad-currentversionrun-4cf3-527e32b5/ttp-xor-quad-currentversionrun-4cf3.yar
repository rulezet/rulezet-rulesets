rule TTP_XOR_QUAD_CurrentVersionRun_4cf3 {
  strings:
    $key_4cf3 = { 1f 9c [2] 3b 92 [2] 10 be [2] 3e 9c [2] 2a 87 [2] 25 9d [2] 3b 80 [2] 39 81 [2] 22 87 [2] 3e 80 [2] 22 af }

  condition:
    any of them
}