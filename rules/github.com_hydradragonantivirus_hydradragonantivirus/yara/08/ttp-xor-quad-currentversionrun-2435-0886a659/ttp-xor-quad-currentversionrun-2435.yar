rule TTP_XOR_QUAD_CurrentVersionRun_2435 {
  strings:
    $key_2435 = { 77 5a [2] 53 54 [2] 78 78 [2] 56 5a [2] 42 41 [2] 4d 5b [2] 53 46 [2] 51 47 [2] 4a 41 [2] 56 46 [2] 4a 69 }

  condition:
    any of them
}