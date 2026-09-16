rule TTP_XOR_QUAD_CurrentVersionRun_73d9 {
  strings:
    $key_73d9 = { 20 b6 [2] 04 b8 [2] 2f 94 [2] 01 b6 [2] 15 ad [2] 1a b7 [2] 04 aa [2] 06 ab [2] 1d ad [2] 01 aa [2] 1d 85 }

  condition:
    any of them
}