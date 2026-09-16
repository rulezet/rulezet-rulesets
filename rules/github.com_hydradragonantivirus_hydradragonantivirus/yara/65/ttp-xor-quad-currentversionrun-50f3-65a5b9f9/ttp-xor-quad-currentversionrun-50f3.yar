rule TTP_XOR_QUAD_CurrentVersionRun_50f3 {
  strings:
    $key_50f3 = { 03 9c [2] 27 92 [2] 0c be [2] 22 9c [2] 36 87 [2] 39 9d [2] 27 80 [2] 25 81 [2] 3e 87 [2] 22 80 [2] 3e af }

  condition:
    any of them
}