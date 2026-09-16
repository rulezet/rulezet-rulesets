rule TTP_XOR_QUAD_CurrentVersionRun_d9dd {
  strings:
    $key_d9dd = { 8a b2 [2] ae bc [2] 85 90 [2] ab b2 [2] bf a9 [2] b0 b3 [2] ae ae [2] ac af [2] b7 a9 [2] ab ae [2] b7 81 }

  condition:
    any of them
}