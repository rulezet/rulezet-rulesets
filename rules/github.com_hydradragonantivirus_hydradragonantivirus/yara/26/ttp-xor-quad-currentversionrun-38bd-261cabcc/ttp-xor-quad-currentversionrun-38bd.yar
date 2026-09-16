rule TTP_XOR_QUAD_CurrentVersionRun_38bd {
  strings:
    $key_38bd = { 6b d2 [2] 4f dc [2] 64 f0 [2] 4a d2 [2] 5e c9 [2] 51 d3 [2] 4f ce [2] 4d cf [2] 56 c9 [2] 4a ce [2] 56 e1 }

  condition:
    any of them
}