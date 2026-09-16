rule TTP_XOR_QUAD_CurrentVersionRun_2529 {
  strings:
    $key_2529 = { 76 46 [2] 52 48 [2] 79 64 [2] 57 46 [2] 43 5d [2] 4c 47 [2] 52 5a [2] 50 5b [2] 4b 5d [2] 57 5a [2] 4b 75 }

  condition:
    any of them
}