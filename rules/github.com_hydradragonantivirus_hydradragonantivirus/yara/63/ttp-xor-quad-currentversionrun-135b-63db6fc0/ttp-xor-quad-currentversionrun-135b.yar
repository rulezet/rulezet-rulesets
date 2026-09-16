rule TTP_XOR_QUAD_CurrentVersionRun_135b {
  strings:
    $key_135b = { 40 34 [2] 64 3a [2] 4f 16 [2] 61 34 [2] 75 2f [2] 7a 35 [2] 64 28 [2] 66 29 [2] 7d 2f [2] 61 28 [2] 7d 07 }

  condition:
    any of them
}