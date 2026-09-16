rule TTP_XOR_QUAD_CurrentVersionRun_55b4 {
  strings:
    $key_55b4 = { 06 db [2] 22 d5 [2] 09 f9 [2] 27 db [2] 33 c0 [2] 3c da [2] 22 c7 [2] 20 c6 [2] 3b c0 [2] 27 c7 [2] 3b e8 }

  condition:
    any of them
}