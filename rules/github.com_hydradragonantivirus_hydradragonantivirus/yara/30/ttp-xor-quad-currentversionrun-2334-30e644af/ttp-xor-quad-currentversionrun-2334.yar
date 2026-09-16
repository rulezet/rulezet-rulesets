rule TTP_XOR_QUAD_CurrentVersionRun_2334 {
  strings:
    $key_2334 = { 70 5b [2] 54 55 [2] 7f 79 [2] 51 5b [2] 45 40 [2] 4a 5a [2] 54 47 [2] 56 46 [2] 4d 40 [2] 51 47 [2] 4d 68 }

  condition:
    any of them
}