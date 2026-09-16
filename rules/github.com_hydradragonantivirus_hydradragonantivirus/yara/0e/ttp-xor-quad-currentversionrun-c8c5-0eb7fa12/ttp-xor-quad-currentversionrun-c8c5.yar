rule TTP_XOR_QUAD_CurrentVersionRun_c8c5 {
  strings:
    $key_c8c5 = { 9b aa [2] bf a4 [2] 94 88 [2] ba aa [2] ae b1 [2] a1 ab [2] bf b6 [2] bd b7 [2] a6 b1 [2] ba b6 [2] a6 99 }

  condition:
    any of them
}