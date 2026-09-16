rule TTP_XOR_QUAD_CurrentVersionRun_0acd {
  strings:
    $key_0acd = { 59 a2 [2] 7d ac [2] 56 80 [2] 78 a2 [2] 6c b9 [2] 63 a3 [2] 7d be [2] 7f bf [2] 64 b9 [2] 78 be [2] 64 91 }

  condition:
    any of them
}