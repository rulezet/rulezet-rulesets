rule TTP_XOR_QUAD_CurrentVersionRun_2052 {
  strings:
    $key_2052 = { 73 3d [2] 57 33 [2] 7c 1f [2] 52 3d [2] 46 26 [2] 49 3c [2] 57 21 [2] 55 20 [2] 4e 26 [2] 52 21 [2] 4e 0e }

  condition:
    any of them
}