rule TTP_XOR_QUAD_CurrentVersionRun_fadf {
  strings:
    $key_fadf = { a9 b0 [2] 8d be [2] a6 92 [2] 88 b0 [2] 9c ab [2] 93 b1 [2] 8d ac [2] 8f ad [2] 94 ab [2] 88 ac [2] 94 83 }

  condition:
    any of them
}