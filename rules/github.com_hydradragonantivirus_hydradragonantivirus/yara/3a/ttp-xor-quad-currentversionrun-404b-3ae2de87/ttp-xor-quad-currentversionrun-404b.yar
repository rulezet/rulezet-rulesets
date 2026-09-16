rule TTP_XOR_QUAD_CurrentVersionRun_404b {
  strings:
    $key_404b = { 13 24 [2] 37 2a [2] 1c 06 [2] 32 24 [2] 26 3f [2] 29 25 [2] 37 38 [2] 35 39 [2] 2e 3f [2] 32 38 [2] 2e 17 }

  condition:
    any of them
}