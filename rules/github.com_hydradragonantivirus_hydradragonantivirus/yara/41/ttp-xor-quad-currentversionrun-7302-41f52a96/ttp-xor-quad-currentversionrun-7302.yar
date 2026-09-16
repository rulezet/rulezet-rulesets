rule TTP_XOR_QUAD_CurrentVersionRun_7302 {
  strings:
    $key_7302 = { 20 6d [2] 04 63 [2] 2f 4f [2] 01 6d [2] 15 76 [2] 1a 6c [2] 04 71 [2] 06 70 [2] 1d 76 [2] 01 71 [2] 1d 5e }

  condition:
    any of them
}