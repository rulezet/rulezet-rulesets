rule TTP_XOR_QUAD_CurrentVersionRun_4a28 {
  strings:
    $key_4a28 = { 19 47 [2] 3d 49 [2] 16 65 [2] 38 47 [2] 2c 5c [2] 23 46 [2] 3d 5b [2] 3f 5a [2] 24 5c [2] 38 5b [2] 24 74 }

  condition:
    any of them
}