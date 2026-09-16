rule TTP_XOR_QUAD_CurrentVersionRun_3d59 {
  strings:
    $key_3d59 = { 6e 36 [2] 4a 38 [2] 61 14 [2] 4f 36 [2] 5b 2d [2] 54 37 [2] 4a 2a [2] 48 2b [2] 53 2d [2] 4f 2a [2] 53 05 }

  condition:
    any of them
}