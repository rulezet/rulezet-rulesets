rule TTP_XOR_QUAD_CurrentVersionRun_3437 {
  strings:
    $key_3437 = { 67 58 [2] 43 56 [2] 68 7a [2] 46 58 [2] 52 43 [2] 5d 59 [2] 43 44 [2] 41 45 [2] 5a 43 [2] 46 44 [2] 5a 6b }

  condition:
    any of them
}