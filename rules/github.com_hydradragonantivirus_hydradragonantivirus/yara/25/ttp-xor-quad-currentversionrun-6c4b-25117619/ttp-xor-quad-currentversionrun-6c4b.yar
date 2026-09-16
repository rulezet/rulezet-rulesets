rule TTP_XOR_QUAD_CurrentVersionRun_6c4b {
  strings:
    $key_6c4b = { 3f 24 [2] 1b 2a [2] 30 06 [2] 1e 24 [2] 0a 3f [2] 05 25 [2] 1b 38 [2] 19 39 [2] 02 3f [2] 1e 38 [2] 02 17 }

  condition:
    any of them
}