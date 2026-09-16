rule TTP_XOR_QUAD_CurrentVersionRun_61f3 {
  strings:
    $key_61f3 = { 32 9c [2] 16 92 [2] 3d be [2] 13 9c [2] 07 87 [2] 08 9d [2] 16 80 [2] 14 81 [2] 0f 87 [2] 13 80 [2] 0f af }

  condition:
    any of them
}