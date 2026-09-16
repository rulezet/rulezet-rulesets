rule TTP_XOR_QUAD_CurrentVersionRun_3ef3 {
  strings:
    $key_3ef3 = { 6d 9c [2] 49 92 [2] 62 be [2] 4c 9c [2] 58 87 [2] 57 9d [2] 49 80 [2] 4b 81 [2] 50 87 [2] 4c 80 [2] 50 af }

  condition:
    any of them
}