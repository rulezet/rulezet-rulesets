rule TTP_XOR_QUAD_CurrentVersionRun_75b4 {
  strings:
    $key_75b4 = { 26 db [2] 02 d5 [2] 29 f9 [2] 07 db [2] 13 c0 [2] 1c da [2] 02 c7 [2] 00 c6 [2] 1b c0 [2] 07 c7 [2] 1b e8 }

  condition:
    any of them
}