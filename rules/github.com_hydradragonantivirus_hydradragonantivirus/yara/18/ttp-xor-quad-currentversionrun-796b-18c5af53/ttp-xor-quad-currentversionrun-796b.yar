rule TTP_XOR_QUAD_CurrentVersionRun_796b {
  strings:
    $key_796b = { 2a 04 [2] 0e 0a [2] 25 26 [2] 0b 04 [2] 1f 1f [2] 10 05 [2] 0e 18 [2] 0c 19 [2] 17 1f [2] 0b 18 [2] 17 37 }

  condition:
    any of them
}