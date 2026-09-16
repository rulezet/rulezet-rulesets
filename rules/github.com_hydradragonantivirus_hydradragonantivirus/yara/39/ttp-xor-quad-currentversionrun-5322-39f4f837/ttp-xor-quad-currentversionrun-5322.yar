rule TTP_XOR_QUAD_CurrentVersionRun_5322 {
  strings:
    $key_5322 = { 00 4d [2] 24 43 [2] 0f 6f [2] 21 4d [2] 35 56 [2] 3a 4c [2] 24 51 [2] 26 50 [2] 3d 56 [2] 21 51 [2] 3d 7e }

  condition:
    any of them
}