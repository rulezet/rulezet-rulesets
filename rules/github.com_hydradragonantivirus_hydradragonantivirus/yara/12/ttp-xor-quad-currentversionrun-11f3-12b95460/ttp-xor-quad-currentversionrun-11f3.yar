rule TTP_XOR_QUAD_CurrentVersionRun_11f3 {
  strings:
    $key_11f3 = { 42 9c [2] 66 92 [2] 4d be [2] 63 9c [2] 77 87 [2] 78 9d [2] 66 80 [2] 64 81 [2] 7f 87 [2] 63 80 [2] 7f af }

  condition:
    any of them
}