rule TTP_XOR_QUAD_CurrentVersionRun_10f3 {
  strings:
    $key_10f3 = { 43 9c [2] 67 92 [2] 4c be [2] 62 9c [2] 76 87 [2] 79 9d [2] 67 80 [2] 65 81 [2] 7e 87 [2] 62 80 [2] 7e af }

  condition:
    any of them
}