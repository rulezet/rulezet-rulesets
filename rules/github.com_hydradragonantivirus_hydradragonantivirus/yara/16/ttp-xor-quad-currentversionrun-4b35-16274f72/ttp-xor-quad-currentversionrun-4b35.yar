rule TTP_XOR_QUAD_CurrentVersionRun_4b35 {
  strings:
    $key_4b35 = { 18 5a [2] 3c 54 [2] 17 78 [2] 39 5a [2] 2d 41 [2] 22 5b [2] 3c 46 [2] 3e 47 [2] 25 41 [2] 39 46 [2] 25 69 }

  condition:
    any of them
}