rule TTP_XOR_QUAD_CurrentVersionRun_01f3 {
  strings:
    $key_01f3 = { 52 9c [2] 76 92 [2] 5d be [2] 73 9c [2] 67 87 [2] 68 9d [2] 76 80 [2] 74 81 [2] 6f 87 [2] 73 80 [2] 6f af }

  condition:
    any of them
}