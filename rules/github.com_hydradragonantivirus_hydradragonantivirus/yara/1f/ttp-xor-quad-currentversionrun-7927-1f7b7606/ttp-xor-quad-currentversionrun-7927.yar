rule TTP_XOR_QUAD_CurrentVersionRun_7927 {
  strings:
    $key_7927 = { 2a 48 [2] 0e 46 [2] 25 6a [2] 0b 48 [2] 1f 53 [2] 10 49 [2] 0e 54 [2] 0c 55 [2] 17 53 [2] 0b 54 [2] 17 7b }

  condition:
    any of them
}