rule TTP_XOR_QUAD_CurrentVersionRun_5a22 {
  strings:
    $key_5a22 = { 09 4d [2] 2d 43 [2] 06 6f [2] 28 4d [2] 3c 56 [2] 33 4c [2] 2d 51 [2] 2f 50 [2] 34 56 [2] 28 51 [2] 34 7e }

  condition:
    any of them
}