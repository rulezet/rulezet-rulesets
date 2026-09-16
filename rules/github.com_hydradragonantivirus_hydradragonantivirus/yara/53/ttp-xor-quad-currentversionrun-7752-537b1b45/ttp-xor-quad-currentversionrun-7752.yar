rule TTP_XOR_QUAD_CurrentVersionRun_7752 {
  strings:
    $key_7752 = { 24 3d [2] 00 33 [2] 2b 1f [2] 05 3d [2] 11 26 [2] 1e 3c [2] 00 21 [2] 02 20 [2] 19 26 [2] 05 21 [2] 19 0e }

  condition:
    any of them
}