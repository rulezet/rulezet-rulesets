rule TTP_XOR_QUAD_CurrentVersionRun_3052 {
  strings:
    $key_3052 = { 63 3d [2] 47 33 [2] 6c 1f [2] 42 3d [2] 56 26 [2] 59 3c [2] 47 21 [2] 45 20 [2] 5e 26 [2] 42 21 [2] 5e 0e }

  condition:
    any of them
}