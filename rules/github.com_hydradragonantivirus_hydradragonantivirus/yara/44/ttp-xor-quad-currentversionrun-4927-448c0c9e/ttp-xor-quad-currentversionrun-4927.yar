rule TTP_XOR_QUAD_CurrentVersionRun_4927 {
  strings:
    $key_4927 = { 1a 48 [2] 3e 46 [2] 15 6a [2] 3b 48 [2] 2f 53 [2] 20 49 [2] 3e 54 [2] 3c 55 [2] 27 53 [2] 3b 54 [2] 27 7b }

  condition:
    any of them
}