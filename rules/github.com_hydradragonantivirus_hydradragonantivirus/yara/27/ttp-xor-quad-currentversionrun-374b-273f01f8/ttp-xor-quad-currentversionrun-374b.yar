rule TTP_XOR_QUAD_CurrentVersionRun_374b {
  strings:
    $key_374b = { 64 24 [2] 40 2a [2] 6b 06 [2] 45 24 [2] 51 3f [2] 5e 25 [2] 40 38 [2] 42 39 [2] 59 3f [2] 45 38 [2] 59 17 }

  condition:
    any of them
}