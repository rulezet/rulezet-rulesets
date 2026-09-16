rule TTP_XOR_QUAD_CurrentVersionRun_0052 {
  strings:
    $key_0052 = { 53 3d [2] 77 33 [2] 5c 1f [2] 72 3d [2] 66 26 [2] 69 3c [2] 77 21 [2] 75 20 [2] 6e 26 [2] 72 21 [2] 6e 0e }

  condition:
    any of them
}