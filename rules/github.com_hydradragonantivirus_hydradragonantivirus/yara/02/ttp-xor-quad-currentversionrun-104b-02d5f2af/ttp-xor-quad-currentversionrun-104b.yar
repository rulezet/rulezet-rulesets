rule TTP_XOR_QUAD_CurrentVersionRun_104b {
  strings:
    $key_104b = { 43 24 [2] 67 2a [2] 4c 06 [2] 62 24 [2] 76 3f [2] 79 25 [2] 67 38 [2] 65 39 [2] 7e 3f [2] 62 38 [2] 7e 17 }

  condition:
    any of them
}