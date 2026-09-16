rule TTP_XOR_QUAD_CurrentVersionRun_4bca {
  strings:
    $key_4bca = { 18 a5 [2] 3c ab [2] 17 87 [2] 39 a5 [2] 2d be [2] 22 a4 [2] 3c b9 [2] 3e b8 [2] 25 be [2] 39 b9 [2] 25 96 }

  condition:
    any of them
}