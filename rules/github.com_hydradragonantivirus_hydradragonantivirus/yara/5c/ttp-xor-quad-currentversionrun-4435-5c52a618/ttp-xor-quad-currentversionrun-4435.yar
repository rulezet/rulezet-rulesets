rule TTP_XOR_QUAD_CurrentVersionRun_4435 {
  strings:
    $key_4435 = { 17 5a [2] 33 54 [2] 18 78 [2] 36 5a [2] 22 41 [2] 2d 5b [2] 33 46 [2] 31 47 [2] 2a 41 [2] 36 46 [2] 2a 69 }

  condition:
    any of them
}