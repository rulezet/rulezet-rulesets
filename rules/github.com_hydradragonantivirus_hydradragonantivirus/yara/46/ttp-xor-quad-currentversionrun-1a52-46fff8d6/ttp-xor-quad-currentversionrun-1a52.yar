rule TTP_XOR_QUAD_CurrentVersionRun_1a52 {
  strings:
    $key_1a52 = { 49 3d [2] 6d 33 [2] 46 1f [2] 68 3d [2] 7c 26 [2] 73 3c [2] 6d 21 [2] 6f 20 [2] 74 26 [2] 68 21 [2] 74 0e }

  condition:
    any of them
}