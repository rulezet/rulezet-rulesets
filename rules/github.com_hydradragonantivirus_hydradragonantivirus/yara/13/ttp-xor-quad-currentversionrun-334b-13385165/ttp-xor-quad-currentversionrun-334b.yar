rule TTP_XOR_QUAD_CurrentVersionRun_334b {
  strings:
    $key_334b = { 60 24 [2] 44 2a [2] 6f 06 [2] 41 24 [2] 55 3f [2] 5a 25 [2] 44 38 [2] 46 39 [2] 5d 3f [2] 41 38 [2] 5d 17 }

  condition:
    any of them
}