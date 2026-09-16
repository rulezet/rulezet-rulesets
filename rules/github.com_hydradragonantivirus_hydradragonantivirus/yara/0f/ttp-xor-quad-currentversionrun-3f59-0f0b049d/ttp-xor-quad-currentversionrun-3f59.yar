rule TTP_XOR_QUAD_CurrentVersionRun_3f59 {
  strings:
    $key_3f59 = { 6c 36 [2] 48 38 [2] 63 14 [2] 4d 36 [2] 59 2d [2] 56 37 [2] 48 2a [2] 4a 2b [2] 51 2d [2] 4d 2a [2] 51 05 }

  condition:
    any of them
}