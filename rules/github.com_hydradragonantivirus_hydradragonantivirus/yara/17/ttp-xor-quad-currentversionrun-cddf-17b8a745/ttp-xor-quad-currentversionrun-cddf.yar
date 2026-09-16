rule TTP_XOR_QUAD_CurrentVersionRun_cddf {
  strings:
    $key_cddf = { 9e b0 [2] ba be [2] 91 92 [2] bf b0 [2] ab ab [2] a4 b1 [2] ba ac [2] b8 ad [2] a3 ab [2] bf ac [2] a3 83 }

  condition:
    any of them
}