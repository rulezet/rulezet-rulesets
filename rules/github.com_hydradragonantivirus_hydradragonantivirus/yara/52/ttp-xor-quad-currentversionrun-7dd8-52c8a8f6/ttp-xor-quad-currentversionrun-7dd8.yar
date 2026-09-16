rule TTP_XOR_QUAD_CurrentVersionRun_7dd8 {
  strings:
    $key_7dd8 = { 2e b7 [2] 0a b9 [2] 21 95 [2] 0f b7 [2] 1b ac [2] 14 b6 [2] 0a ab [2] 08 aa [2] 13 ac [2] 0f ab [2] 13 84 }

  condition:
    any of them
}