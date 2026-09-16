rule TTP_XOR_QUAD_CurrentVersionRun_561b {
  strings:
    $key_561b = { 05 74 [2] 21 7a [2] 0a 56 [2] 24 74 [2] 30 6f [2] 3f 75 [2] 21 68 [2] 23 69 [2] 38 6f [2] 24 68 [2] 38 47 }

  condition:
    any of them
}