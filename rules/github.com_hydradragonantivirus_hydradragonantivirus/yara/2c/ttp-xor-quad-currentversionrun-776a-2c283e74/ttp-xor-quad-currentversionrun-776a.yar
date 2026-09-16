rule TTP_XOR_QUAD_CurrentVersionRun_776a {
  strings:
    $key_776a = { 24 05 [2] 00 0b [2] 2b 27 [2] 05 05 [2] 11 1e [2] 1e 04 [2] 00 19 [2] 02 18 [2] 19 1e [2] 05 19 [2] 19 36 }

  condition:
    any of them
}