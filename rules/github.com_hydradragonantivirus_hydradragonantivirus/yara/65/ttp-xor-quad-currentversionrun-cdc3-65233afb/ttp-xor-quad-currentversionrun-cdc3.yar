rule TTP_XOR_QUAD_CurrentVersionRun_cdc3 {
  strings:
    $key_cdc3 = { 9e ac [2] ba a2 [2] 91 8e [2] bf ac [2] ab b7 [2] a4 ad [2] ba b0 [2] b8 b1 [2] a3 b7 [2] bf b0 [2] a3 9f }

  condition:
    any of them
}