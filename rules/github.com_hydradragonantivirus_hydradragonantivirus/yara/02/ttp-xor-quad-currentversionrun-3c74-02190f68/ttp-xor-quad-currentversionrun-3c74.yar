rule TTP_XOR_QUAD_CurrentVersionRun_3c74 {
  strings:
    $key_3c74 = { 6f 1b [2] 4b 15 [2] 60 39 [2] 4e 1b [2] 5a 00 [2] 55 1a [2] 4b 07 [2] 49 06 [2] 52 00 [2] 4e 07 [2] 52 28 }

  condition:
    any of them
}