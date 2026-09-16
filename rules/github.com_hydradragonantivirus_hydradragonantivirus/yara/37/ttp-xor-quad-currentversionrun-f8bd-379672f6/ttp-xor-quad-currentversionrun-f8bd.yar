rule TTP_XOR_QUAD_CurrentVersionRun_f8bd {
  strings:
    $key_f8bd = { ab d2 [2] 8f dc [2] a4 f0 [2] 8a d2 [2] 9e c9 [2] 91 d3 [2] 8f ce [2] 8d cf [2] 96 c9 [2] 8a ce [2] 96 e1 }

  condition:
    any of them
}