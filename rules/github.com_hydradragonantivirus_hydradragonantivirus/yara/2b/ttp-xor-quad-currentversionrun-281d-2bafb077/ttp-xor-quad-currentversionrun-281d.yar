rule TTP_XOR_QUAD_CurrentVersionRun_281d {
  strings:
    $key_281d = { 7b 72 [2] 5f 7c [2] 74 50 [2] 5a 72 [2] 4e 69 [2] 41 73 [2] 5f 6e [2] 5d 6f [2] 46 69 [2] 5a 6e [2] 46 41 }

  condition:
    any of them
}