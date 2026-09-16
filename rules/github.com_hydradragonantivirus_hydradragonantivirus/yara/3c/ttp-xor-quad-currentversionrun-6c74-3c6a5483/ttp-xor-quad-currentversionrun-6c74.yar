rule TTP_XOR_QUAD_CurrentVersionRun_6c74 {
  strings:
    $key_6c74 = { 3f 1b [2] 1b 15 [2] 30 39 [2] 1e 1b [2] 0a 00 [2] 05 1a [2] 1b 07 [2] 19 06 [2] 02 00 [2] 1e 07 [2] 02 28 }

  condition:
    any of them
}