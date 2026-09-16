rule TTP_XOR_QUAD_CurrentVersionRun_c8d9 {
  strings:
    $key_c8d9 = { 9b b6 [2] bf b8 [2] 94 94 [2] ba b6 [2] ae ad [2] a1 b7 [2] bf aa [2] bd ab [2] a6 ad [2] ba aa [2] a6 85 }

  condition:
    any of them
}