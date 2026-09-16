rule TTP_XOR_QUAD_CurrentVersionRun_30e7 {
  strings:
    $key_30e7 = { 63 88 [2] 47 86 [2] 6c aa [2] 42 88 [2] 56 93 [2] 59 89 [2] 47 94 [2] 45 95 [2] 5e 93 [2] 42 94 [2] 5e bb }

  condition:
    any of them
}