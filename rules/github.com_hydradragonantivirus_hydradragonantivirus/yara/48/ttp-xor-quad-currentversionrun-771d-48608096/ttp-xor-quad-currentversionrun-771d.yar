rule TTP_XOR_QUAD_CurrentVersionRun_771d {
  strings:
    $key_771d = { 24 72 [2] 00 7c [2] 2b 50 [2] 05 72 [2] 11 69 [2] 1e 73 [2] 00 6e [2] 02 6f [2] 19 69 [2] 05 6e [2] 19 41 }

  condition:
    any of them
}