rule TTP_XOR_QUAD_CurrentVersionRun_03ba {
  strings:
    $key_03ba = { 50 d5 [2] 74 db [2] 5f f7 [2] 71 d5 [2] 65 ce [2] 6a d4 [2] 74 c9 [2] 76 c8 [2] 6d ce [2] 71 c9 [2] 6d e6 }

  condition:
    any of them
}