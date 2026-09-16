rule TTP_XOR_QUAD_CurrentVersionRun_6a22 {
  strings:
    $key_6a22 = { 39 4d [2] 1d 43 [2] 36 6f [2] 18 4d [2] 0c 56 [2] 03 4c [2] 1d 51 [2] 1f 50 [2] 04 56 [2] 18 51 [2] 04 7e }

  condition:
    any of them
}