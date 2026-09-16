rule TTP_XOR_QUAD_CurrentVersionRun_601b {
  strings:
    $key_601b = { 33 74 [2] 17 7a [2] 3c 56 [2] 12 74 [2] 06 6f [2] 09 75 [2] 17 68 [2] 15 69 [2] 0e 6f [2] 12 68 [2] 0e 47 }

  condition:
    any of them
}