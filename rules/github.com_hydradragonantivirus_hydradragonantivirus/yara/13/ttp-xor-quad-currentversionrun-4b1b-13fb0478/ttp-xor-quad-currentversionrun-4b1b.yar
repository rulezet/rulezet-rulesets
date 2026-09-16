rule TTP_XOR_QUAD_CurrentVersionRun_4b1b {
  strings:
    $key_4b1b = { 18 74 [2] 3c 7a [2] 17 56 [2] 39 74 [2] 2d 6f [2] 22 75 [2] 3c 68 [2] 3e 69 [2] 25 6f [2] 39 68 [2] 25 47 }

  condition:
    any of them
}