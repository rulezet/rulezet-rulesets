rule TTP_XOR_QUAD_CurrentVersionRun_10d8 {
  strings:
    $key_10d8 = { 43 b7 [2] 67 b9 [2] 4c 95 [2] 62 b7 [2] 76 ac [2] 79 b6 [2] 67 ab [2] 65 aa [2] 7e ac [2] 62 ab [2] 7e 84 }

  condition:
    any of them
}