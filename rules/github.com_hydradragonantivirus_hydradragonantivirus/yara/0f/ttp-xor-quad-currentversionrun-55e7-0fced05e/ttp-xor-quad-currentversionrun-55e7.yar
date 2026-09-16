rule TTP_XOR_QUAD_CurrentVersionRun_55e7 {
  strings:
    $key_55e7 = { 06 88 [2] 22 86 [2] 09 aa [2] 27 88 [2] 33 93 [2] 3c 89 [2] 22 94 [2] 20 95 [2] 3b 93 [2] 27 94 [2] 3b bb }

  condition:
    any of them
}