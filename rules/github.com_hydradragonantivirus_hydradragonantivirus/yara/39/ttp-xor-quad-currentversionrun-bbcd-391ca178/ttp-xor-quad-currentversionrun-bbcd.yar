rule TTP_XOR_QUAD_CurrentVersionRun_bbcd {
  strings:
    $key_bbcd = { e8 a2 [2] cc ac [2] e7 80 [2] c9 a2 [2] dd b9 [2] d2 a3 [2] cc be [2] ce bf [2] d5 b9 [2] c9 be [2] d5 91 }

  condition:
    any of them
}