rule TTP_XOR_QUAD_CurrentVersionRun_7cf3 {
  strings:
    $key_7cf3 = { 2f 9c [2] 0b 92 [2] 20 be [2] 0e 9c [2] 1a 87 [2] 15 9d [2] 0b 80 [2] 09 81 [2] 12 87 [2] 0e 80 [2] 12 af }

  condition:
    any of them
}