rule TTP_XOR_QUAD_CurrentVersionRun_76f3 {
  strings:
    $key_76f3 = { 25 9c [2] 01 92 [2] 2a be [2] 04 9c [2] 10 87 [2] 1f 9d [2] 01 80 [2] 03 81 [2] 18 87 [2] 04 80 [2] 18 af }

  condition:
    any of them
}