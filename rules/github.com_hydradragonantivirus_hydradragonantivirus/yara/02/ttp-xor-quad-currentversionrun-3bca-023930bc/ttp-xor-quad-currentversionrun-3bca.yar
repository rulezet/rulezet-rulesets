rule TTP_XOR_QUAD_CurrentVersionRun_3bca {
  strings:
    $key_3bca = { 68 a5 [2] 4c ab [2] 67 87 [2] 49 a5 [2] 5d be [2] 52 a4 [2] 4c b9 [2] 4e b8 [2] 55 be [2] 49 b9 [2] 55 96 }

  condition:
    any of them
}