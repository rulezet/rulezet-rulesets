rule TTP_XOR_QUAD_CurrentVersionRun_e8bf {
  strings:
    $key_e8bf = { bb d0 [2] 9f de [2] b4 f2 [2] 9a d0 [2] 8e cb [2] 81 d1 [2] 9f cc [2] 9d cd [2] 86 cb [2] 9a cc [2] 86 e3 }

  condition:
    any of them
}