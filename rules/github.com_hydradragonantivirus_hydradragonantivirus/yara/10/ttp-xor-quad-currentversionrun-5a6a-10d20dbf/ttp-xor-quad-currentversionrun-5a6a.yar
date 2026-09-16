rule TTP_XOR_QUAD_CurrentVersionRun_5a6a {
  strings:
    $key_5a6a = { 09 05 [2] 2d 0b [2] 06 27 [2] 28 05 [2] 3c 1e [2] 33 04 [2] 2d 19 [2] 2f 18 [2] 34 1e [2] 28 19 [2] 34 36 }

  condition:
    any of them
}