rule TTP_XOR_QUAD_CurrentVersionRun_38f3 {
  strings:
    $key_38f3 = { 6b 9c [2] 4f 92 [2] 64 be [2] 4a 9c [2] 5e 87 [2] 51 9d [2] 4f 80 [2] 4d 81 [2] 56 87 [2] 4a 80 [2] 56 af }

  condition:
    any of them
}