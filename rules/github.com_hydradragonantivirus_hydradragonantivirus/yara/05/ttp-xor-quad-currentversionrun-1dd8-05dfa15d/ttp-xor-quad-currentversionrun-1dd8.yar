rule TTP_XOR_QUAD_CurrentVersionRun_1dd8 {
  strings:
    $key_1dd8 = { 4e b7 [2] 6a b9 [2] 41 95 [2] 6f b7 [2] 7b ac [2] 74 b6 [2] 6a ab [2] 68 aa [2] 73 ac [2] 6f ab [2] 73 84 }

  condition:
    any of them
}