rule TTP_XOR_QUAD_CurrentVersionRun_2bca {
  strings:
    $key_2bca = { 78 a5 [2] 5c ab [2] 77 87 [2] 59 a5 [2] 4d be [2] 42 a4 [2] 5c b9 [2] 5e b8 [2] 45 be [2] 59 b9 [2] 45 96 }

  condition:
    any of them
}