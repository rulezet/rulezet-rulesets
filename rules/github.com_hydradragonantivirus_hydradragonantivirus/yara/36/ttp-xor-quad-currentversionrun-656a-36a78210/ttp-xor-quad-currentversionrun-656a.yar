rule TTP_XOR_QUAD_CurrentVersionRun_656a {
  strings:
    $key_656a = { 36 05 [2] 12 0b [2] 39 27 [2] 17 05 [2] 03 1e [2] 0c 04 [2] 12 19 [2] 10 18 [2] 0b 1e [2] 17 19 [2] 0b 36 }

  condition:
    any of them
}