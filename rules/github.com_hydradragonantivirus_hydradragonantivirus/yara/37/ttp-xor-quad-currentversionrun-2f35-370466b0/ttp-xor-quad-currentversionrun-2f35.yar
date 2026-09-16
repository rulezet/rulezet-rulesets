rule TTP_XOR_QUAD_CurrentVersionRun_2f35 {
  strings:
    $key_2f35 = { 7c 5a [2] 58 54 [2] 73 78 [2] 5d 5a [2] 49 41 [2] 46 5b [2] 58 46 [2] 5a 47 [2] 41 41 [2] 5d 46 [2] 41 69 }

  condition:
    any of them
}