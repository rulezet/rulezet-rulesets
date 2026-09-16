rule TTP_XOR_QUAD_CurrentVersionRun_2957 {
  strings:
    $key_2957 = { 7a 38 [2] 5e 36 [2] 75 1a [2] 5b 38 [2] 4f 23 [2] 40 39 [2] 5e 24 [2] 5c 25 [2] 47 23 [2] 5b 24 [2] 47 0b }

  condition:
    any of them
}