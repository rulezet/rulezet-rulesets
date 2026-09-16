rule TTP_XOR_QUAD_CurrentVersionRun_64ba {
  strings:
    $key_64ba = { 37 d5 [2] 13 db [2] 38 f7 [2] 16 d5 [2] 02 ce [2] 0d d4 [2] 13 c9 [2] 11 c8 [2] 0a ce [2] 16 c9 [2] 0a e6 }

  condition:
    any of them
}