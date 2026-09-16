rule TTP_XOR_QUAD_CurrentVersionRun_58bf {
  strings:
    $key_58bf = { 0b d0 [2] 2f de [2] 04 f2 [2] 2a d0 [2] 3e cb [2] 31 d1 [2] 2f cc [2] 2d cd [2] 36 cb [2] 2a cc [2] 36 e3 }

  condition:
    any of them
}