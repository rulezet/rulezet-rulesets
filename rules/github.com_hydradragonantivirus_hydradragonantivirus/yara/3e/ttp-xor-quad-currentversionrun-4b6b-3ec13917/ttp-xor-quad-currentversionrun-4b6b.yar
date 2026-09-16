rule TTP_XOR_QUAD_CurrentVersionRun_4b6b {
  strings:
    $key_4b6b = { 18 04 [2] 3c 0a [2] 17 26 [2] 39 04 [2] 2d 1f [2] 22 05 [2] 3c 18 [2] 3e 19 [2] 25 1f [2] 39 18 [2] 25 37 }

  condition:
    any of them
}