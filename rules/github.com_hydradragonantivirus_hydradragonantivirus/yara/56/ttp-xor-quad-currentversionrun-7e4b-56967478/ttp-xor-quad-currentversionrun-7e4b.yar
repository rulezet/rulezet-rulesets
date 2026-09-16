rule TTP_XOR_QUAD_CurrentVersionRun_7e4b {
  strings:
    $key_7e4b = { 2d 24 [2] 09 2a [2] 22 06 [2] 0c 24 [2] 18 3f [2] 17 25 [2] 09 38 [2] 0b 39 [2] 10 3f [2] 0c 38 [2] 10 17 }

  condition:
    any of them
}