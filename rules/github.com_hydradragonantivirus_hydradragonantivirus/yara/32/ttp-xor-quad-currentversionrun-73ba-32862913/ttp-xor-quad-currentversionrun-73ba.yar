rule TTP_XOR_QUAD_CurrentVersionRun_73ba {
  strings:
    $key_73ba = { 20 d5 [2] 04 db [2] 2f f7 [2] 01 d5 [2] 15 ce [2] 1a d4 [2] 04 c9 [2] 06 c8 [2] 1d ce [2] 01 c9 [2] 1d e6 }

  condition:
    any of them
}