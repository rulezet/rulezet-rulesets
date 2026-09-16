rule TTP_XOR_QUAD_CurrentVersionRun_4832 {
  strings:
    $key_4832 = { 1b 5d [2] 3f 53 [2] 14 7f [2] 3a 5d [2] 2e 46 [2] 21 5c [2] 3f 41 [2] 3d 40 [2] 26 46 [2] 3a 41 [2] 26 6e }

  condition:
    any of them
}