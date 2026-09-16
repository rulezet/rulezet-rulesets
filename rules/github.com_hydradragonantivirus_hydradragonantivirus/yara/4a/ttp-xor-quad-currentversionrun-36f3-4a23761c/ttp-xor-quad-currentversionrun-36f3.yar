rule TTP_XOR_QUAD_CurrentVersionRun_36f3 {
  strings:
    $key_36f3 = { 65 9c [2] 41 92 [2] 6a be [2] 44 9c [2] 50 87 [2] 5f 9d [2] 41 80 [2] 43 81 [2] 58 87 [2] 44 80 [2] 58 af }

  condition:
    any of them
}