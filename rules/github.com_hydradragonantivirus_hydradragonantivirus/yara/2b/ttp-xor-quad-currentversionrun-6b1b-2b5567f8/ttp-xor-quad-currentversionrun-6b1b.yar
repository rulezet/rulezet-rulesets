rule TTP_XOR_QUAD_CurrentVersionRun_6b1b {
  strings:
    $key_6b1b = { 38 74 [2] 1c 7a [2] 37 56 [2] 19 74 [2] 0d 6f [2] 02 75 [2] 1c 68 [2] 1e 69 [2] 05 6f [2] 19 68 [2] 05 47 }

  condition:
    any of them
}