rule TTP_XOR_QUAD_CurrentVersionRun_1b27 {
  strings:
    $key_1b27 = { 48 48 [2] 6c 46 [2] 47 6a [2] 69 48 [2] 7d 53 [2] 72 49 [2] 6c 54 [2] 6e 55 [2] 75 53 [2] 69 54 [2] 75 7b }

  condition:
    any of them
}