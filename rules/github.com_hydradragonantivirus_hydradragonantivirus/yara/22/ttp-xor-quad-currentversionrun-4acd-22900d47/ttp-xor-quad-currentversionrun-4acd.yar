rule TTP_XOR_QUAD_CurrentVersionRun_4acd {
  strings:
    $key_4acd = { 19 a2 [2] 3d ac [2] 16 80 [2] 38 a2 [2] 2c b9 [2] 23 a3 [2] 3d be [2] 3f bf [2] 24 b9 [2] 38 be [2] 24 91 }

  condition:
    any of them
}