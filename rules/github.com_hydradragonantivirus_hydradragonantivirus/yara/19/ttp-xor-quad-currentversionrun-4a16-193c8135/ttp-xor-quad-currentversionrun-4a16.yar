rule TTP_XOR_QUAD_CurrentVersionRun_4a16 {
  strings:
    $key_4a16 = { 19 79 [2] 3d 77 [2] 16 5b [2] 38 79 [2] 2c 62 [2] 23 78 [2] 3d 65 [2] 3f 64 [2] 24 62 [2] 38 65 [2] 24 4a }

  condition:
    any of them
}