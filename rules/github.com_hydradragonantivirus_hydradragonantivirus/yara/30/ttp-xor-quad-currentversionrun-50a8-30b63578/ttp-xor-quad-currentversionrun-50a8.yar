rule TTP_XOR_QUAD_CurrentVersionRun_50a8 {
  strings:
    $key_50a8 = { 03 c7 [2] 27 c9 [2] 0c e5 [2] 22 c7 [2] 36 dc [2] 39 c6 [2] 27 db [2] 25 da [2] 3e dc [2] 22 db [2] 3e f4 }

  condition:
    any of them
}