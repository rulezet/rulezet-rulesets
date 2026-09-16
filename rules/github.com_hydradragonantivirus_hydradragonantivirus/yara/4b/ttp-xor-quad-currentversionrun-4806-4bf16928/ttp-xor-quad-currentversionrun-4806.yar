rule TTP_XOR_QUAD_CurrentVersionRun_4806 {
  strings:
    $key_4806 = { 1b 69 [2] 3f 67 [2] 14 4b [2] 3a 69 [2] 2e 72 [2] 21 68 [2] 3f 75 [2] 3d 74 [2] 26 72 [2] 3a 75 [2] 26 5a }

  condition:
    any of them
}