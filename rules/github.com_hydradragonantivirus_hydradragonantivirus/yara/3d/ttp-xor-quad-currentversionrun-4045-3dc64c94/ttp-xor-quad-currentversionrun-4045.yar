rule TTP_XOR_QUAD_CurrentVersionRun_4045 {
  strings:
    $key_4045 = { 13 2a [2] 37 24 [2] 1c 08 [2] 32 2a [2] 26 31 [2] 29 2b [2] 37 36 [2] 35 37 [2] 2e 31 [2] 32 36 [2] 2e 19 }

  condition:
    any of them
}