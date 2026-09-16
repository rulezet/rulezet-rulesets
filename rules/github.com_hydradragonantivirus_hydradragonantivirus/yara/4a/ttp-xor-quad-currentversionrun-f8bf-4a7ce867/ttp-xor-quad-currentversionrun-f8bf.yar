rule TTP_XOR_QUAD_CurrentVersionRun_f8bf {
  strings:
    $key_f8bf = { ab d0 [2] 8f de [2] a4 f2 [2] 8a d0 [2] 9e cb [2] 91 d1 [2] 8f cc [2] 8d cd [2] 96 cb [2] 8a cc [2] 96 e3 }

  condition:
    any of them
}