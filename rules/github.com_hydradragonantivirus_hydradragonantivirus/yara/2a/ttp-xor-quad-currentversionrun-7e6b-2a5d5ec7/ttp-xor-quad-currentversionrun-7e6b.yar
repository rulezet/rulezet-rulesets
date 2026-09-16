rule TTP_XOR_QUAD_CurrentVersionRun_7e6b {
  strings:
    $key_7e6b = { 2d 04 [2] 09 0a [2] 22 26 [2] 0c 04 [2] 18 1f [2] 17 05 [2] 09 18 [2] 0b 19 [2] 10 1f [2] 0c 18 [2] 10 37 }

  condition:
    any of them
}