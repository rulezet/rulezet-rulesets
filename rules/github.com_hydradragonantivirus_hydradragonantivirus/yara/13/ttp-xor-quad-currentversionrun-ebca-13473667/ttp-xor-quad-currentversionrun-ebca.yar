rule TTP_XOR_QUAD_CurrentVersionRun_ebca {
  strings:
    $key_ebca = { b8 a5 [2] 9c ab [2] b7 87 [2] 99 a5 [2] 8d be [2] 82 a4 [2] 9c b9 [2] 9e b8 [2] 85 be [2] 99 b9 [2] 85 96 }

  condition:
    any of them
}