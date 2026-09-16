rule TTP_XOR_QUAD_CurrentVersionRun_34e7 {
  strings:
    $key_34e7 = { 67 88 [2] 43 86 [2] 68 aa [2] 46 88 [2] 52 93 [2] 5d 89 [2] 43 94 [2] 41 95 [2] 5a 93 [2] 46 94 [2] 5a bb }

  condition:
    any of them
}