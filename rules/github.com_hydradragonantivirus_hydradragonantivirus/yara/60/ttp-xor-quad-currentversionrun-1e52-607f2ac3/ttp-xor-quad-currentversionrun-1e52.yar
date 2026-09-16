rule TTP_XOR_QUAD_CurrentVersionRun_1e52 {
  strings:
    $key_1e52 = { 4d 3d [2] 69 33 [2] 42 1f [2] 6c 3d [2] 78 26 [2] 77 3c [2] 69 21 [2] 6b 20 [2] 70 26 [2] 6c 21 [2] 70 0e }

  condition:
    any of them
}