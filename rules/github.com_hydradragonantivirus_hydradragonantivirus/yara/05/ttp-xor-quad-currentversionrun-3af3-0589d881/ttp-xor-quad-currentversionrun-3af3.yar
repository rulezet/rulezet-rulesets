rule TTP_XOR_QUAD_CurrentVersionRun_3af3 {
  strings:
    $key_3af3 = { 69 9c [2] 4d 92 [2] 66 be [2] 48 9c [2] 5c 87 [2] 53 9d [2] 4d 80 [2] 4f 81 [2] 54 87 [2] 48 80 [2] 54 af }

  condition:
    any of them
}