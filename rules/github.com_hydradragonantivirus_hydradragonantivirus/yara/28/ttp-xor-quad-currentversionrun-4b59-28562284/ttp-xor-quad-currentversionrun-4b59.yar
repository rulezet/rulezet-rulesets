rule TTP_XOR_QUAD_CurrentVersionRun_4b59 {
  strings:
    $key_4b59 = { 18 36 [2] 3c 38 [2] 17 14 [2] 39 36 [2] 2d 2d [2] 22 37 [2] 3c 2a [2] 3e 2b [2] 25 2d [2] 39 2a [2] 25 05 }

  condition:
    any of them
}