rule TTP_XOR_QUAD_CurrentVersionRun_3527 {
  strings:
    $key_3527 = { 66 48 [2] 42 46 [2] 69 6a [2] 47 48 [2] 53 53 [2] 5c 49 [2] 42 54 [2] 40 55 [2] 5b 53 [2] 47 54 [2] 5b 7b }

  condition:
    any of them
}