rule TTP_XOR_QUAD_CurrentVersionRun_064b {
  strings:
    $key_064b = { 55 24 [2] 71 2a [2] 5a 06 [2] 74 24 [2] 60 3f [2] 6f 25 [2] 71 38 [2] 73 39 [2] 68 3f [2] 74 38 [2] 68 17 }

  condition:
    any of them
}