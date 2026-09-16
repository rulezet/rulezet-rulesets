rule TTP_XOR_QUAD_CurrentVersionRun_6f35 {
  strings:
    $key_6f35 = { 3c 5a [2] 18 54 [2] 33 78 [2] 1d 5a [2] 09 41 [2] 06 5b [2] 18 46 [2] 1a 47 [2] 01 41 [2] 1d 46 [2] 01 69 }

  condition:
    any of them
}