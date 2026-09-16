rule TTP_XOR_QUAD_CurrentVersionRun_3a27 {
  strings:
    $key_3a27 = { 69 48 [2] 4d 46 [2] 66 6a [2] 48 48 [2] 5c 53 [2] 53 49 [2] 4d 54 [2] 4f 55 [2] 54 53 [2] 48 54 [2] 54 7b }

  condition:
    any of them
}