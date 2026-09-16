rule TTP_XOR_QUAD_CurrentVersionRun_4844 {
  strings:
    $key_4844 = { 1b 2b [2] 3f 25 [2] 14 09 [2] 3a 2b [2] 2e 30 [2] 21 2a [2] 3f 37 [2] 3d 36 [2] 26 30 [2] 3a 37 [2] 26 18 }

  condition:
    any of them
}