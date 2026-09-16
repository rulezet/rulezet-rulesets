rule TTP_XOR_QUAD_CurrentVersionRun_3ff3 {
  strings:
    $key_3ff3 = { 6c 9c [2] 48 92 [2] 63 be [2] 4d 9c [2] 59 87 [2] 56 9d [2] 48 80 [2] 4a 81 [2] 51 87 [2] 4d 80 [2] 51 af }

  condition:
    any of them
}