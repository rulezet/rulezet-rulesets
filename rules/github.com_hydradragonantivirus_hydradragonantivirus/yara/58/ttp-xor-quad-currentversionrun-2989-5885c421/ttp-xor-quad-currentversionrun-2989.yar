rule TTP_XOR_QUAD_CurrentVersionRun_2989 {
  strings:
    $key_2989 = { 7a e6 [2] 5e e8 [2] 75 c4 [2] 5b e6 [2] 4f fd [2] 40 e7 [2] 5e fa [2] 5c fb [2] 47 fd [2] 5b fa [2] 47 d5 }

  condition:
    any of them
}