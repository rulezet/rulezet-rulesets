rule TTP_XOR_QUAD_CurrentVersionRun_0e6b {
  strings:
    $key_0e6b = { 5d 04 [2] 79 0a [2] 52 26 [2] 7c 04 [2] 68 1f [2] 67 05 [2] 79 18 [2] 7b 19 [2] 60 1f [2] 7c 18 [2] 60 37 }

  condition:
    any of them
}