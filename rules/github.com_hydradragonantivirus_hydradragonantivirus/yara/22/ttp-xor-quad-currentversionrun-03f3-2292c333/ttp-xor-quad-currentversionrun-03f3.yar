rule TTP_XOR_QUAD_CurrentVersionRun_03f3 {
  strings:
    $key_03f3 = { 50 9c [2] 74 92 [2] 5f be [2] 71 9c [2] 65 87 [2] 6a 9d [2] 74 80 [2] 76 81 [2] 6d 87 [2] 71 80 [2] 6d af }

  condition:
    any of them
}