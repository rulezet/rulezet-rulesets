rule TTP_XOR_QUAD_CurrentVersionRun_730b {
  strings:
    $key_730b = { 20 64 [2] 04 6a [2] 2f 46 [2] 01 64 [2] 15 7f [2] 1a 65 [2] 04 78 [2] 06 79 [2] 1d 7f [2] 01 78 [2] 1d 57 }

  condition:
    any of them
}