rule TTP_XOR_QUAD_CurrentVersionRun_51f3 {
  strings:
    $key_51f3 = { 02 9c [2] 26 92 [2] 0d be [2] 23 9c [2] 37 87 [2] 38 9d [2] 26 80 [2] 24 81 [2] 3f 87 [2] 23 80 [2] 3f af }

  condition:
    any of them
}