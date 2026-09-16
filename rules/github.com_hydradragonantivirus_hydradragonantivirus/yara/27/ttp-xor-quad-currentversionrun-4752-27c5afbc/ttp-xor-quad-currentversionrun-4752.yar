rule TTP_XOR_QUAD_CurrentVersionRun_4752 {
  strings:
    $key_4752 = { 14 3d [2] 30 33 [2] 1b 1f [2] 35 3d [2] 21 26 [2] 2e 3c [2] 30 21 [2] 32 20 [2] 29 26 [2] 35 21 [2] 29 0e }

  condition:
    any of them
}