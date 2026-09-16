rule TTP_XOR_QUAD_CurrentVersionRun_c8c4 {
  strings:
    $key_c8c4 = { 9b ab [2] bf a5 [2] 94 89 [2] ba ab [2] ae b0 [2] a1 aa [2] bf b7 [2] bd b6 [2] a6 b0 [2] ba b7 [2] a6 98 }

  condition:
    any of them
}