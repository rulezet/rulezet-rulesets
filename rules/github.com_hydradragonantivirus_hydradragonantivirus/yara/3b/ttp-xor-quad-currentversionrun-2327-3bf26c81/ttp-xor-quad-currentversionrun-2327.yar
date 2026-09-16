rule TTP_XOR_QUAD_CurrentVersionRun_2327 {
  strings:
    $key_2327 = { 70 48 [2] 54 46 [2] 7f 6a [2] 51 48 [2] 45 53 [2] 4a 49 [2] 54 54 [2] 56 55 [2] 4d 53 [2] 51 54 [2] 4d 7b }

  condition:
    any of them
}