rule TTP_XOR_QUAD_CurrentVersionRun_761b {
  strings:
    $key_761b = { 25 74 [2] 01 7a [2] 2a 56 [2] 04 74 [2] 10 6f [2] 1f 75 [2] 01 68 [2] 03 69 [2] 18 6f [2] 04 68 [2] 18 47 }

  condition:
    any of them
}