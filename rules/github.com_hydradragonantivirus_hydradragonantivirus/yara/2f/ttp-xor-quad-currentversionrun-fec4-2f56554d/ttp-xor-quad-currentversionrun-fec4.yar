rule TTP_XOR_QUAD_CurrentVersionRun_fec4 {
  strings:
    $key_fec4 = { ad ab [2] 89 a5 [2] a2 89 [2] 8c ab [2] 98 b0 [2] 97 aa [2] 89 b7 [2] 8b b6 [2] 90 b0 [2] 8c b7 [2] 90 98 }

  condition:
    any of them
}