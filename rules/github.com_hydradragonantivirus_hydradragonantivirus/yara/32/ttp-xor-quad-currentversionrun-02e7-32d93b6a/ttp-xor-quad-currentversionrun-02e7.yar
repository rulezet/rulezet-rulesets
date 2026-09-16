rule TTP_XOR_QUAD_CurrentVersionRun_02e7 {
  strings:
    $key_02e7 = { 51 88 [2] 75 86 [2] 5e aa [2] 70 88 [2] 64 93 [2] 6b 89 [2] 75 94 [2] 77 95 [2] 6c 93 [2] 70 94 [2] 6c bb }

  condition:
    any of them
}