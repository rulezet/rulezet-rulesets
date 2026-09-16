rule TTP_XOR_QUAD_CurrentVersionRun_224b {
  strings:
    $key_224b = { 71 24 [2] 55 2a [2] 7e 06 [2] 50 24 [2] 44 3f [2] 4b 25 [2] 55 38 [2] 57 39 [2] 4c 3f [2] 50 38 [2] 4c 17 }

  condition:
    any of them
}