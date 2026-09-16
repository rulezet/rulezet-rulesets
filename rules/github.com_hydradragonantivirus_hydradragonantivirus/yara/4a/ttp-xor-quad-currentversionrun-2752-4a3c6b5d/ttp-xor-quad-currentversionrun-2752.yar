rule TTP_XOR_QUAD_CurrentVersionRun_2752 {
  strings:
    $key_2752 = { 74 3d [2] 50 33 [2] 7b 1f [2] 55 3d [2] 41 26 [2] 4e 3c [2] 50 21 [2] 52 20 [2] 49 26 [2] 55 21 [2] 49 0e }

  condition:
    any of them
}