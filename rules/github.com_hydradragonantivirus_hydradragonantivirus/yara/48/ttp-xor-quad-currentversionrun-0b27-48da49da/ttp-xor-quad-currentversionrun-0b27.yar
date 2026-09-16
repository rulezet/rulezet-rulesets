rule TTP_XOR_QUAD_CurrentVersionRun_0b27 {
  strings:
    $key_0b27 = { 58 48 [2] 7c 46 [2] 57 6a [2] 79 48 [2] 6d 53 [2] 62 49 [2] 7c 54 [2] 7e 55 [2] 65 53 [2] 79 54 [2] 65 7b }

  condition:
    any of them
}