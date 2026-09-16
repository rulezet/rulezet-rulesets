rule TTP_XOR_QUAD_CurrentVersionRun_4e6a {
  strings:
    $key_4e6a = { 1d 05 [2] 39 0b [2] 12 27 [2] 3c 05 [2] 28 1e [2] 27 04 [2] 39 19 [2] 3b 18 [2] 20 1e [2] 3c 19 [2] 20 36 }

  condition:
    any of them
}