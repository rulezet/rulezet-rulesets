rule TTP_XOR_QUAD_CurrentVersionRun_771a {
  strings:
    $key_771a = { 24 75 [2] 00 7b [2] 2b 57 [2] 05 75 [2] 11 6e [2] 1e 74 [2] 00 69 [2] 02 68 [2] 19 6e [2] 05 69 [2] 19 46 }

  condition:
    any of them
}