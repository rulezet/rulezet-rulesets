rule TTP_XOR_QUAD_CurrentVersionRun_7b6a {
  strings:
    $key_7b6a = { 28 05 [2] 0c 0b [2] 27 27 [2] 09 05 [2] 1d 1e [2] 12 04 [2] 0c 19 [2] 0e 18 [2] 15 1e [2] 09 19 [2] 15 36 }

  condition:
    any of them
}