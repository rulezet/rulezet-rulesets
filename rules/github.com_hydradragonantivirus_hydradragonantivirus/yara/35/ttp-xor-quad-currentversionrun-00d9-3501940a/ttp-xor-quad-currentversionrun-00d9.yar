rule TTP_XOR_QUAD_CurrentVersionRun_00d9 {
  strings:
    $key_00d9 = { 53 b6 [2] 77 b8 [2] 5c 94 [2] 72 b6 [2] 66 ad [2] 69 b7 [2] 77 aa [2] 75 ab [2] 6e ad [2] 72 aa [2] 6e 85 }

  condition:
    any of them
}