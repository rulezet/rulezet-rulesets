rule TTP_XOR_QUAD_CurrentVersionRun_596b {
  strings:
    $key_596b = { 0a 04 [2] 2e 0a [2] 05 26 [2] 2b 04 [2] 3f 1f [2] 30 05 [2] 2e 18 [2] 2c 19 [2] 37 1f [2] 2b 18 [2] 37 37 }

  condition:
    any of them
}