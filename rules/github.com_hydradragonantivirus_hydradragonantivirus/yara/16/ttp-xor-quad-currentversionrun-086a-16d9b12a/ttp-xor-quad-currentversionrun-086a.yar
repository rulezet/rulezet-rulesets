rule TTP_XOR_QUAD_CurrentVersionRun_086a {
  strings:
    $key_086a = { 5b 05 [2] 7f 0b [2] 54 27 [2] 7a 05 [2] 6e 1e [2] 61 04 [2] 7f 19 [2] 7d 18 [2] 66 1e [2] 7a 19 [2] 66 36 }

  condition:
    any of them
}