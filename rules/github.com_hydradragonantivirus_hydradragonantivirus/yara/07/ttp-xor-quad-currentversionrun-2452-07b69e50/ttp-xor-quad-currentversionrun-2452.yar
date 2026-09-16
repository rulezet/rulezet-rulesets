rule TTP_XOR_QUAD_CurrentVersionRun_2452 {
  strings:
    $key_2452 = { 77 3d [2] 53 33 [2] 78 1f [2] 56 3d [2] 42 26 [2] 4d 3c [2] 53 21 [2] 51 20 [2] 4a 26 [2] 56 21 [2] 4a 0e }

  condition:
    any of them
}