rule TTP_XOR_QUAD_CurrentVersionRun_4c27 {
  strings:
    $key_4c27 = { 1f 48 [2] 3b 46 [2] 10 6a [2] 3e 48 [2] 2a 53 [2] 25 49 [2] 3b 54 [2] 39 55 [2] 22 53 [2] 3e 54 [2] 22 7b }

  condition:
    any of them
}