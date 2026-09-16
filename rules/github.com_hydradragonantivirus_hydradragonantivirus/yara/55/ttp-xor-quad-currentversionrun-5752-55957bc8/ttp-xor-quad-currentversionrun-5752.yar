rule TTP_XOR_QUAD_CurrentVersionRun_5752 {
  strings:
    $key_5752 = { 04 3d [2] 20 33 [2] 0b 1f [2] 25 3d [2] 31 26 [2] 3e 3c [2] 20 21 [2] 22 20 [2] 39 26 [2] 25 21 [2] 39 0e }

  condition:
    any of them
}