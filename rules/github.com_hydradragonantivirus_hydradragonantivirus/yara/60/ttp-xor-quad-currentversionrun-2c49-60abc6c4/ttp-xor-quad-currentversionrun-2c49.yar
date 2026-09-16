rule TTP_XOR_QUAD_CurrentVersionRun_2c49 {
  strings:
    $key_2c49 = { 7f 26 [2] 5b 28 [2] 70 04 [2] 5e 26 [2] 4a 3d [2] 45 27 [2] 5b 3a [2] 59 3b [2] 42 3d [2] 5e 3a [2] 42 15 }

  condition:
    any of them
}