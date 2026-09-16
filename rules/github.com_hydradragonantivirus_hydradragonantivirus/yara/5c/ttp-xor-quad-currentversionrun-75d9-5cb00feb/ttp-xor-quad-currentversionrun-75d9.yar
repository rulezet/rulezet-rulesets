rule TTP_XOR_QUAD_CurrentVersionRun_75d9 {
  strings:
    $key_75d9 = { 26 b6 [2] 02 b8 [2] 29 94 [2] 07 b6 [2] 13 ad [2] 1c b7 [2] 02 aa [2] 00 ab [2] 1b ad [2] 07 aa [2] 1b 85 }

  condition:
    any of them
}