rule TTP_XOR_QUAD_CurrentVersionRun_e8bd {
  strings:
    $key_e8bd = { bb d2 [2] 9f dc [2] b4 f0 [2] 9a d2 [2] 8e c9 [2] 81 d3 [2] 9f ce [2] 9d cf [2] 86 c9 [2] 9a ce [2] 86 e1 }

  condition:
    any of them
}