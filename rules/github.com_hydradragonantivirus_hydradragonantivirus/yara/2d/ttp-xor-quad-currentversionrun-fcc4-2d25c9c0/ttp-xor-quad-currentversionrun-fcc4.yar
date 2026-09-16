rule TTP_XOR_QUAD_CurrentVersionRun_fcc4 {
  strings:
    $key_fcc4 = { af ab [2] 8b a5 [2] a0 89 [2] 8e ab [2] 9a b0 [2] 95 aa [2] 8b b7 [2] 89 b6 [2] 92 b0 [2] 8e b7 [2] 92 98 }

  condition:
    any of them
}