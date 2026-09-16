rule TTP_XOR_QUAD_CurrentVersionRun_4829 {
  strings:
    $key_4829 = { 1b 46 [2] 3f 48 [2] 14 64 [2] 3a 46 [2] 2e 5d [2] 21 47 [2] 3f 5a [2] 3d 5b [2] 26 5d [2] 3a 5a [2] 26 75 }

  condition:
    any of them
}