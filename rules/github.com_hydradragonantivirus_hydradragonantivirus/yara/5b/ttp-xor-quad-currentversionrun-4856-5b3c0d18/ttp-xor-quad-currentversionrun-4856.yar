rule TTP_XOR_QUAD_CurrentVersionRun_4856 {
  strings:
    $key_4856 = { 1b 39 [2] 3f 37 [2] 14 1b [2] 3a 39 [2] 2e 22 [2] 21 38 [2] 3f 25 [2] 3d 24 [2] 26 22 [2] 3a 25 [2] 26 0a }

  condition:
    any of them
}