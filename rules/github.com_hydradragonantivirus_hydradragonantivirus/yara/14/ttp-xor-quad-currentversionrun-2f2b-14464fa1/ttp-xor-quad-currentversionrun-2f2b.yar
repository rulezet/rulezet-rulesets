rule TTP_XOR_QUAD_CurrentVersionRun_2f2b {
  strings:
    $key_2f2b = { 7c 44 [2] 58 4a [2] 73 66 [2] 5d 44 [2] 49 5f [2] 46 45 [2] 58 58 [2] 5a 59 [2] 41 5f [2] 5d 58 [2] 41 77 }

  condition:
    any of them
}