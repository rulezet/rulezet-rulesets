rule TTP_XOR_QUAD_CurrentVersionRun_1752 {
  strings:
    $key_1752 = { 44 3d [2] 60 33 [2] 4b 1f [2] 65 3d [2] 71 26 [2] 7e 3c [2] 60 21 [2] 62 20 [2] 79 26 [2] 65 21 [2] 79 0e }

  condition:
    any of them
}