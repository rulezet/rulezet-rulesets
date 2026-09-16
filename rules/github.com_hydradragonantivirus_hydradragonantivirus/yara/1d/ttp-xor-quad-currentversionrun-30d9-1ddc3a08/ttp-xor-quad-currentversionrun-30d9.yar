rule TTP_XOR_QUAD_CurrentVersionRun_30d9 {
  strings:
    $key_30d9 = { 63 b6 [2] 47 b8 [2] 6c 94 [2] 42 b6 [2] 56 ad [2] 59 b7 [2] 47 aa [2] 45 ab [2] 5e ad [2] 42 aa [2] 5e 85 }

  condition:
    any of them
}