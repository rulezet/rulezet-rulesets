rule TTP_XOR_QUAD_CurrentVersionRun_7717 {
  strings:
    $key_7717 = { 24 78 [2] 00 76 [2] 2b 5a [2] 05 78 [2] 11 63 [2] 1e 79 [2] 00 64 [2] 02 65 [2] 19 63 [2] 05 64 [2] 19 4b }

  condition:
    any of them
}