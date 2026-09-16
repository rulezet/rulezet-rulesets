rule TTP_XOR_QUAD_CurrentVersionRun_0f59 {
  strings:
    $key_0f59 = { 5c 36 [2] 78 38 [2] 53 14 [2] 7d 36 [2] 69 2d [2] 66 37 [2] 78 2a [2] 7a 2b [2] 61 2d [2] 7d 2a [2] 61 05 }

  condition:
    any of them
}