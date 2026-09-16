rule TTP_XOR_QUAD_CurrentVersionRun_7fd9 {
  strings:
    $key_7fd9 = { 2c b6 [2] 08 b8 [2] 23 94 [2] 0d b6 [2] 19 ad [2] 16 b7 [2] 08 aa [2] 0a ab [2] 11 ad [2] 0d aa [2] 11 85 }

  condition:
    any of them
}