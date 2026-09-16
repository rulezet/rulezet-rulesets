rule TTP_XOR_QUAD_CurrentVersionRun_6dc2 {
  strings:
    $key_6dc2 = { 3e ad [2] 1a a3 [2] 31 8f [2] 1f ad [2] 0b b6 [2] 04 ac [2] 1a b1 [2] 18 b0 [2] 03 b6 [2] 1f b1 [2] 03 9e }

  condition:
    any of them
}