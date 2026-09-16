rule TTP_XOR_QUAD_CurrentVersionRun_7701 {
  strings:
    $key_7701 = { 24 6e [2] 00 60 [2] 2b 4c [2] 05 6e [2] 11 75 [2] 1e 6f [2] 00 72 [2] 02 73 [2] 19 75 [2] 05 72 [2] 19 5d }

  condition:
    any of them
}