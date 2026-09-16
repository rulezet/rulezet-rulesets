rule TTP_XOR_QUAD_CurrentVersionRun_7cc2 {
  strings:
    $key_7cc2 = { 2f ad [2] 0b a3 [2] 20 8f [2] 0e ad [2] 1a b6 [2] 15 ac [2] 0b b1 [2] 09 b0 [2] 12 b6 [2] 0e b1 [2] 12 9e }

  condition:
    any of them
}