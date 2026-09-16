rule TTP_XOR_QUAD_CurrentVersionRun_636a {
  strings:
    $key_636a = { 30 05 [2] 14 0b [2] 3f 27 [2] 11 05 [2] 05 1e [2] 0a 04 [2] 14 19 [2] 16 18 [2] 0d 1e [2] 11 19 [2] 0d 36 }

  condition:
    any of them
}