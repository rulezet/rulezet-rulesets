rule TTP_XOR_QUAD_CurrentVersionRun_40e7 {
  strings:
    $key_40e7 = { 13 88 [2] 37 86 [2] 1c aa [2] 32 88 [2] 26 93 [2] 29 89 [2] 37 94 [2] 35 95 [2] 2e 93 [2] 32 94 [2] 2e bb }

  condition:
    any of them
}