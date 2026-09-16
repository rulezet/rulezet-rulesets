rule TTP_XOR_QUAD_CurrentVersionRun_facd {
  strings:
    $key_facd = { a9 a2 [2] 8d ac [2] a6 80 [2] 88 a2 [2] 9c b9 [2] 93 a3 [2] 8d be [2] 8f bf [2] 94 b9 [2] 88 be [2] 94 91 }

  condition:
    any of them
}