rule TTP_XOR_QUAD_CurrentVersionRun_44c2 {
  strings:
    $key_44c2 = { 17 ad [2] 33 a3 [2] 18 8f [2] 36 ad [2] 22 b6 [2] 2d ac [2] 33 b1 [2] 31 b0 [2] 2a b6 [2] 36 b1 [2] 2a 9e }

  condition:
    any of them
}