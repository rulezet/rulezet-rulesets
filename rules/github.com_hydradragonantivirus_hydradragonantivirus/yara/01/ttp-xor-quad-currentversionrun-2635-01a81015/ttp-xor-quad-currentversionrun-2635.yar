rule TTP_XOR_QUAD_CurrentVersionRun_2635 {
  strings:
    $key_2635 = { 75 5a [2] 51 54 [2] 7a 78 [2] 54 5a [2] 40 41 [2] 4f 5b [2] 51 46 [2] 53 47 [2] 48 41 [2] 54 46 [2] 48 69 }

  condition:
    any of them
}