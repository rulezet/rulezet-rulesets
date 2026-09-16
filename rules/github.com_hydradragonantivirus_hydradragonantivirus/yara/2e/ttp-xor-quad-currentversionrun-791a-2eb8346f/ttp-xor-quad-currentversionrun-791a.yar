rule TTP_XOR_QUAD_CurrentVersionRun_791a {
  strings:
    $key_791a = { 2a 75 [2] 0e 7b [2] 25 57 [2] 0b 75 [2] 1f 6e [2] 10 74 [2] 0e 69 [2] 0c 68 [2] 17 6e [2] 0b 69 [2] 17 46 }

  condition:
    any of them
}