rule TTP_XOR_QUAD_CurrentVersionRun_4f06 {
  strings:
    $key_4f06 = { 1c 69 [2] 38 67 [2] 13 4b [2] 3d 69 [2] 29 72 [2] 26 68 [2] 38 75 [2] 3a 74 [2] 21 72 [2] 3d 75 [2] 21 5a }

  condition:
    any of them
}