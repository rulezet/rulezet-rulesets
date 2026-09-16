rule TTP_XOR_QUAD_CurrentVersionRun_32d9 {
  strings:
    $key_32d9 = { 61 b6 [2] 45 b8 [2] 6e 94 [2] 40 b6 [2] 54 ad [2] 5b b7 [2] 45 aa [2] 47 ab [2] 5c ad [2] 40 aa [2] 5c 85 }

  condition:
    any of them
}