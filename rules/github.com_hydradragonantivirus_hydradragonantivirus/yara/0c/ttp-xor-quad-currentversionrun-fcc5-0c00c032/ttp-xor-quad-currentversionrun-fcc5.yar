rule TTP_XOR_QUAD_CurrentVersionRun_fcc5 {
  strings:
    $key_fcc5 = { af aa [2] 8b a4 [2] a0 88 [2] 8e aa [2] 9a b1 [2] 95 ab [2] 8b b6 [2] 89 b7 [2] 92 b1 [2] 8e b6 [2] 92 99 }

  condition:
    any of them
}