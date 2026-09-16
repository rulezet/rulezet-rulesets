rule TTP_XOR_QUAD_CurrentVersionRun_00d8 {
  strings:
    $key_00d8 = { 53 b7 [2] 77 b9 [2] 5c 95 [2] 72 b7 [2] 66 ac [2] 69 b6 [2] 77 ab [2] 75 aa [2] 6e ac [2] 72 ab [2] 6e 84 }

  condition:
    any of them
}