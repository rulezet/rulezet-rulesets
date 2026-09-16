rule TTP_XOR_QUAD_CurrentVersionRun_0c6b {
  strings:
    $key_0c6b = { 5f 04 [2] 7b 0a [2] 50 26 [2] 7e 04 [2] 6a 1f [2] 65 05 [2] 7b 18 [2] 79 19 [2] 62 1f [2] 7e 18 [2] 62 37 }

  condition:
    any of them
}