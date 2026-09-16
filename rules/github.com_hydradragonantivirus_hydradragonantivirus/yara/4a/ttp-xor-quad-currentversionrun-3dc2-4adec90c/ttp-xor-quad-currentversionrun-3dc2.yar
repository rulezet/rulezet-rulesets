rule TTP_XOR_QUAD_CurrentVersionRun_3dc2 {
  strings:
    $key_3dc2 = { 6e ad [2] 4a a3 [2] 61 8f [2] 4f ad [2] 5b b6 [2] 54 ac [2] 4a b1 [2] 48 b0 [2] 53 b6 [2] 4f b1 [2] 53 9e }

  condition:
    any of them
}