rule TTP_XOR_QUAD_CurrentVersionRun_5332 {
  strings:
    $key_5332 = { 00 5d [2] 24 53 [2] 0f 7f [2] 21 5d [2] 35 46 [2] 3a 5c [2] 24 41 [2] 26 40 [2] 3d 46 [2] 21 41 [2] 3d 6e }

  condition:
    any of them
}