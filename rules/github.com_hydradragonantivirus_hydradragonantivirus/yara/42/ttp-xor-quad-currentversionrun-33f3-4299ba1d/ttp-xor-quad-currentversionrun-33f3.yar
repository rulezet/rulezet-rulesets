rule TTP_XOR_QUAD_CurrentVersionRun_33f3 {
  strings:
    $key_33f3 = { 60 9c [2] 44 92 [2] 6f be [2] 41 9c [2] 55 87 [2] 5a 9d [2] 44 80 [2] 46 81 [2] 5d 87 [2] 41 80 [2] 5d af }

  condition:
    any of them
}