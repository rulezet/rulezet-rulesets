rule TTP_XOR_QUAD_CurrentVersionRun_39c4 {
  strings:
    $key_39c4 = { 6a ab [2] 4e a5 [2] 65 89 [2] 4b ab [2] 5f b0 [2] 50 aa [2] 4e b7 [2] 4c b6 [2] 57 b0 [2] 4b b7 [2] 57 98 }

  condition:
    any of them
}