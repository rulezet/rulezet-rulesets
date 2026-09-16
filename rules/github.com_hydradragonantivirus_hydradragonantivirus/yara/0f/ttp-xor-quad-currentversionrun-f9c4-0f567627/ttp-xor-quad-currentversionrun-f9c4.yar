rule TTP_XOR_QUAD_CurrentVersionRun_f9c4 {
  strings:
    $key_f9c4 = { aa ab [2] 8e a5 [2] a5 89 [2] 8b ab [2] 9f b0 [2] 90 aa [2] 8e b7 [2] 8c b6 [2] 97 b0 [2] 8b b7 [2] 97 98 }

  condition:
    any of them
}