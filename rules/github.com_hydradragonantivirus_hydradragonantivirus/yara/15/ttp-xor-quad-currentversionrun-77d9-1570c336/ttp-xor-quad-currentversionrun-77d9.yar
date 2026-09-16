rule TTP_XOR_QUAD_CurrentVersionRun_77d9 {
  strings:
    $key_77d9 = { 24 b6 [2] 00 b8 [2] 2b 94 [2] 05 b6 [2] 11 ad [2] 1e b7 [2] 00 aa [2] 02 ab [2] 19 ad [2] 05 aa [2] 19 85 }

  condition:
    any of them
}