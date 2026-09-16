rule TTP_XOR_QUAD_CurrentVersionRun_0e27 {
  strings:
    $key_0e27 = { 5d 48 [2] 79 46 [2] 52 6a [2] 7c 48 [2] 68 53 [2] 67 49 [2] 79 54 [2] 7b 55 [2] 60 53 [2] 7c 54 [2] 60 7b }

  condition:
    any of them
}