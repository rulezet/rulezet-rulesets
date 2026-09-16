rule TTP_XOR_QUAD_CurrentVersionRun_3552 {
  strings:
    $key_3552 = { 66 3d [2] 42 33 [2] 69 1f [2] 47 3d [2] 53 26 [2] 5c 3c [2] 42 21 [2] 40 20 [2] 5b 26 [2] 47 21 [2] 5b 0e }

  condition:
    any of them
}