rule TTP_XOR_QUAD_CurrentVersionRun_efbf {
  strings:
    $key_efbf = { bc d0 [2] 98 de [2] b3 f2 [2] 9d d0 [2] 89 cb [2] 86 d1 [2] 98 cc [2] 9a cd [2] 81 cb [2] 9d cc [2] 81 e3 }

  condition:
    any of them
}