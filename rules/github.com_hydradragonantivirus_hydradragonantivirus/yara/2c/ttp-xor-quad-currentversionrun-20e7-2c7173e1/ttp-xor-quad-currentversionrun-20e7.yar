rule TTP_XOR_QUAD_CurrentVersionRun_20e7 {
  strings:
    $key_20e7 = { 73 88 [2] 57 86 [2] 7c aa [2] 52 88 [2] 46 93 [2] 49 89 [2] 57 94 [2] 55 95 [2] 4e 93 [2] 52 94 [2] 4e bb }

  condition:
    any of them
}