rule TTP_XOR_QUAD_CurrentVersionRun_3a59 {
  strings:
    $key_3a59 = { 69 36 [2] 4d 38 [2] 66 14 [2] 48 36 [2] 5c 2d [2] 53 37 [2] 4d 2a [2] 4f 2b [2] 54 2d [2] 48 2a [2] 54 05 }

  condition:
    any of them
}