rule TTP_XOR_QUAD_CurrentVersionRun_4122 {
  strings:
    $key_4122 = { 12 4d [2] 36 43 [2] 1d 6f [2] 33 4d [2] 27 56 [2] 28 4c [2] 36 51 [2] 34 50 [2] 2f 56 [2] 33 51 [2] 2f 7e }

  condition:
    any of them
}