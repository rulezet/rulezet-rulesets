rule TTP_XOR_QUAD_CurrentVersionRun_edc2 {
  strings:
    $key_edc2 = { be ad [2] 9a a3 [2] b1 8f [2] 9f ad [2] 8b b6 [2] 84 ac [2] 9a b1 [2] 98 b0 [2] 83 b6 [2] 9f b1 [2] 83 9e }

  condition:
    any of them
}