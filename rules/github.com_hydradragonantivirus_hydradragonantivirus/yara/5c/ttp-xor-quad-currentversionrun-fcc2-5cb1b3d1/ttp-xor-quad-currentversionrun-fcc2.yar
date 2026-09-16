rule TTP_XOR_QUAD_CurrentVersionRun_fcc2 {
  strings:
    $key_fcc2 = { af ad [2] 8b a3 [2] a0 8f [2] 8e ad [2] 9a b6 [2] 95 ac [2] 8b b1 [2] 89 b0 [2] 92 b6 [2] 8e b1 [2] 92 9e }

  condition:
    any of them
}