rule TTP_XOR_QUAD_CurrentVersionRun_586a {
  strings:
    $key_586a = { 0b 05 [2] 2f 0b [2] 04 27 [2] 2a 05 [2] 3e 1e [2] 31 04 [2] 2f 19 [2] 2d 18 [2] 36 1e [2] 2a 19 [2] 36 36 }

  condition:
    any of them
}