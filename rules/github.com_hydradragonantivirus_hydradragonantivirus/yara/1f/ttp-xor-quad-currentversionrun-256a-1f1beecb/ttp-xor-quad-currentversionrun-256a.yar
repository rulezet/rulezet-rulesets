rule TTP_XOR_QUAD_CurrentVersionRun_256a {
  strings:
    $key_256a = { 76 05 [2] 52 0b [2] 79 27 [2] 57 05 [2] 43 1e [2] 4c 04 [2] 52 19 [2] 50 18 [2] 4b 1e [2] 57 19 [2] 4b 36 }

  condition:
    any of them
}