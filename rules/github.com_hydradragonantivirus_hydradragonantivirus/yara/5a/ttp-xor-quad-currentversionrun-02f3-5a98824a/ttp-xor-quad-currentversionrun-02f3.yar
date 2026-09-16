rule TTP_XOR_QUAD_CurrentVersionRun_02f3 {
  strings:
    $key_02f3 = { 51 9c [2] 75 92 [2] 5e be [2] 70 9c [2] 64 87 [2] 6b 9d [2] 75 80 [2] 77 81 [2] 6c 87 [2] 70 80 [2] 6c af }

  condition:
    any of them
}