rule TTP_XOR_QUAD_CurrentVersionRun_1552 {
  strings:
    $key_1552 = { 46 3d [2] 62 33 [2] 49 1f [2] 67 3d [2] 73 26 [2] 7c 3c [2] 62 21 [2] 60 20 [2] 7b 26 [2] 67 21 [2] 7b 0e }

  condition:
    any of them
}