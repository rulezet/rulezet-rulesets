rule TTP_XOR_QUAD_CurrentVersionRun_586b {
  strings:
    $key_586b = { 0b 04 [2] 2f 0a [2] 04 26 [2] 2a 04 [2] 3e 1f [2] 31 05 [2] 2f 18 [2] 2d 19 [2] 36 1f [2] 2a 18 [2] 36 37 }

  condition:
    any of them
}