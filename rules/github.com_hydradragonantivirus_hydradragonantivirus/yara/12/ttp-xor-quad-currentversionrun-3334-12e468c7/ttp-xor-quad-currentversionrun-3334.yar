rule TTP_XOR_QUAD_CurrentVersionRun_3334 {
  strings:
    $key_3334 = { 60 5b [2] 44 55 [2] 6f 79 [2] 41 5b [2] 55 40 [2] 5a 5a [2] 44 47 [2] 46 46 [2] 5d 40 [2] 41 47 [2] 5d 68 }

  condition:
    any of them
}