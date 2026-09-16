rule TTP_XOR_QUAD_CurrentVersionRun_2bd9 {
  strings:
    $key_2bd9 = { 78 b6 [2] 5c b8 [2] 77 94 [2] 59 b6 [2] 4d ad [2] 42 b7 [2] 5c aa [2] 5e ab [2] 45 ad [2] 59 aa [2] 45 85 }

  condition:
    any of them
}