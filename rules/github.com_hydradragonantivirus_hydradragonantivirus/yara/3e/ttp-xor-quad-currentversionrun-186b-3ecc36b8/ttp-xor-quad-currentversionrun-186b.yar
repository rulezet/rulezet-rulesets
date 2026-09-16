rule TTP_XOR_QUAD_CurrentVersionRun_186b {
  strings:
    $key_186b = { 4b 04 [2] 6f 0a [2] 44 26 [2] 6a 04 [2] 7e 1f [2] 71 05 [2] 6f 18 [2] 6d 19 [2] 76 1f [2] 6a 18 [2] 76 37 }

  condition:
    any of them
}