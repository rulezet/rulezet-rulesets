rule TTP_XOR_QUAD_CurrentVersionRun_3acd {
  strings:
    $key_3acd = { 69 a2 [2] 4d ac [2] 66 80 [2] 48 a2 [2] 5c b9 [2] 53 a3 [2] 4d be [2] 4f bf [2] 54 b9 [2] 48 be [2] 54 91 }

  condition:
    any of them
}