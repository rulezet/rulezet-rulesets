rule TTP_XOR_QUAD_CurrentVersionRun_efba {
  strings:
    $key_efba = { bc d5 [2] 98 db [2] b3 f7 [2] 9d d5 [2] 89 ce [2] 86 d4 [2] 98 c9 [2] 9a c8 [2] 81 ce [2] 9d c9 [2] 81 e6 }

  condition:
    any of them
}