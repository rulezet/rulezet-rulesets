rule TTP_XOR_QUAD_CurrentVersionRun_5f35 {
  strings:
    $key_5f35 = { 0c 5a [2] 28 54 [2] 03 78 [2] 2d 5a [2] 39 41 [2] 36 5b [2] 28 46 [2] 2a 47 [2] 31 41 [2] 2d 46 [2] 31 69 }

  condition:
    any of them
}