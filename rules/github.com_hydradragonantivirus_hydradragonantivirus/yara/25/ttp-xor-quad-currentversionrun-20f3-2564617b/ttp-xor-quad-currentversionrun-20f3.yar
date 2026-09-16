rule TTP_XOR_QUAD_CurrentVersionRun_20f3 {
  strings:
    $key_20f3 = { 73 9c [2] 57 92 [2] 7c be [2] 52 9c [2] 46 87 [2] 49 9d [2] 57 80 [2] 55 81 [2] 4e 87 [2] 52 80 [2] 4e af }

  condition:
    any of them
}