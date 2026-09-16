rule TTP_XOR_QUAD_CurrentVersionRun_2d27 {
  strings:
    $key_2d27 = { 7e 48 [2] 5a 46 [2] 71 6a [2] 5f 48 [2] 4b 53 [2] 44 49 [2] 5a 54 [2] 58 55 [2] 43 53 [2] 5f 54 [2] 43 7b }

  condition:
    any of them
}