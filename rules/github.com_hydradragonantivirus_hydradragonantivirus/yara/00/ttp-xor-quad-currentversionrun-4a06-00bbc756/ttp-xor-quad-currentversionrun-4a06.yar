rule TTP_XOR_QUAD_CurrentVersionRun_4a06 {
  strings:
    $key_4a06 = { 19 69 [2] 3d 67 [2] 16 4b [2] 38 69 [2] 2c 72 [2] 23 68 [2] 3d 75 [2] 3f 74 [2] 24 72 [2] 38 75 [2] 24 5a }

  condition:
    any of them
}