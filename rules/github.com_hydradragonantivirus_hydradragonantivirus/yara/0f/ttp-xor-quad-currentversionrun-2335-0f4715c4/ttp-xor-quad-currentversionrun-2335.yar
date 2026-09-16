rule TTP_XOR_QUAD_CurrentVersionRun_2335 {
  strings:
    $key_2335 = { 70 5a [2] 54 54 [2] 7f 78 [2] 51 5a [2] 45 41 [2] 4a 5b [2] 54 46 [2] 56 47 [2] 4d 41 [2] 51 46 [2] 4d 69 }

  condition:
    any of them
}