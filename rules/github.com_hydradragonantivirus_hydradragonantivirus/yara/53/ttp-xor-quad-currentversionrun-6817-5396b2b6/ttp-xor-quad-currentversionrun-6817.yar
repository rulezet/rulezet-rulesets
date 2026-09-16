rule TTP_XOR_QUAD_CurrentVersionRun_6817 {
  strings:
    $key_6817 = { 3b 78 [2] 1f 76 [2] 34 5a [2] 1a 78 [2] 0e 63 [2] 01 79 [2] 1f 64 [2] 1d 65 [2] 06 63 [2] 1a 64 [2] 06 4b }

  condition:
    any of them
}