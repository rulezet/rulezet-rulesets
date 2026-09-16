rule TTP_XOR_QUAD_CurrentVersionRun_484b {
  strings:
    $key_484b = { 1b 24 [2] 3f 2a [2] 14 06 [2] 3a 24 [2] 2e 3f [2] 21 25 [2] 3f 38 [2] 3d 39 [2] 26 3f [2] 3a 38 [2] 26 17 }

  condition:
    any of them
}