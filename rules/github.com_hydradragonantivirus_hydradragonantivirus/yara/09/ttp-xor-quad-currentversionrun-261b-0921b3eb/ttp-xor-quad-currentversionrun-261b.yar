rule TTP_XOR_QUAD_CurrentVersionRun_261b {
  strings:
    $key_261b = { 75 74 [2] 51 7a [2] 7a 56 [2] 54 74 [2] 40 6f [2] 4f 75 [2] 51 68 [2] 53 69 [2] 48 6f [2] 54 68 [2] 48 47 }

  condition:
    any of them
}