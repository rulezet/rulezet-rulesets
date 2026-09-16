rule TTP_XOR_QUAD_CurrentVersionRun_f1f3 {
  strings:
    $key_f1f3 = { a2 9c [2] 86 92 [2] ad be [2] 83 9c [2] 97 87 [2] 98 9d [2] 86 80 [2] 84 81 [2] 9f 87 [2] 83 80 [2] 9f af }

  condition:
    any of them
}