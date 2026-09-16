rule TTP_XOR_QUAD_CurrentVersionRun_17f3 {
  strings:
    $key_17f3 = { 44 9c [2] 60 92 [2] 4b be [2] 65 9c [2] 71 87 [2] 7e 9d [2] 60 80 [2] 62 81 [2] 79 87 [2] 65 80 [2] 79 af }

  condition:
    any of them
}