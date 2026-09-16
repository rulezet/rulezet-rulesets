rule TTP_XOR_QUAD_CurrentVersionRun_48f3 {
  strings:
    $key_48f3 = { 1b 9c [2] 3f 92 [2] 14 be [2] 3a 9c [2] 2e 87 [2] 21 9d [2] 3f 80 [2] 3d 81 [2] 26 87 [2] 3a 80 [2] 26 af }

  condition:
    any of them
}