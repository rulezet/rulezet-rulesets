rule TTP_XOR_QUAD_CurrentVersionRun_e752 {
  strings:
    $key_e752 = { b4 3d [2] 90 33 [2] bb 1f [2] 95 3d [2] 81 26 [2] 8e 3c [2] 90 21 [2] 92 20 [2] 89 26 [2] 95 21 [2] 89 0e }

  condition:
    any of them
}