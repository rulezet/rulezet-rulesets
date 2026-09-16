rule TTP_XOR_QUAD_CurrentVersionRun_efca {
  strings:
    $key_efca = { bc a5 [2] 98 ab [2] b3 87 [2] 9d a5 [2] 89 be [2] 86 a4 [2] 98 b9 [2] 9a b8 [2] 81 be [2] 9d b9 [2] 81 96 }

  condition:
    any of them
}