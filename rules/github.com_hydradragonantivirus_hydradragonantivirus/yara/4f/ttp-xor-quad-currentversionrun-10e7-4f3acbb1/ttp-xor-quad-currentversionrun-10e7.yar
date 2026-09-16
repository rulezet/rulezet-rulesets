rule TTP_XOR_QUAD_CurrentVersionRun_10e7 {
  strings:
    $key_10e7 = { 43 88 [2] 67 86 [2] 4c aa [2] 62 88 [2] 76 93 [2] 79 89 [2] 67 94 [2] 65 95 [2] 7e 93 [2] 62 94 [2] 7e bb }

  condition:
    any of them
}