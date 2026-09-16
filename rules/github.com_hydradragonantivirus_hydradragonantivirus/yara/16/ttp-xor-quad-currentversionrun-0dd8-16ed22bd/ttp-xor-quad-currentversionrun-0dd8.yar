rule TTP_XOR_QUAD_CurrentVersionRun_0dd8 {
  strings:
    $key_0dd8 = { 5e b7 [2] 7a b9 [2] 51 95 [2] 7f b7 [2] 6b ac [2] 64 b6 [2] 7a ab [2] 78 aa [2] 63 ac [2] 7f ab [2] 63 84 }

  condition:
    any of them
}