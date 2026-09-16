rule TTP_XOR_QUAD_CurrentVersionRun_3c4b {
  strings:
    $key_3c4b = { 6f 24 [2] 4b 2a [2] 60 06 [2] 4e 24 [2] 5a 3f [2] 55 25 [2] 4b 38 [2] 49 39 [2] 52 3f [2] 4e 38 [2] 52 17 }

  condition:
    any of them
}