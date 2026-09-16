rule TTP_XOR_QUAD_CurrentVersionRun_431b {
  strings:
    $key_431b = { 10 74 [2] 34 7a [2] 1f 56 [2] 31 74 [2] 25 6f [2] 2a 75 [2] 34 68 [2] 36 69 [2] 2d 6f [2] 31 68 [2] 2d 47 }

  condition:
    any of them
}