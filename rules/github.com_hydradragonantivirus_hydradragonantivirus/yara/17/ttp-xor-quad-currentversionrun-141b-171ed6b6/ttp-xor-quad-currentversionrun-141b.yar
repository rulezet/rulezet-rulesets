rule TTP_XOR_QUAD_CurrentVersionRun_141b {
  strings:
    $key_141b = { 47 74 [2] 63 7a [2] 48 56 [2] 66 74 [2] 72 6f [2] 7d 75 [2] 63 68 [2] 61 69 [2] 7a 6f [2] 66 68 [2] 7a 47 }

  condition:
    any of them
}