rule TTP_XOR_QUAD_CurrentVersionRun_cac4 {
  strings:
    $key_cac4 = { 99 ab [2] bd a5 [2] 96 89 [2] b8 ab [2] ac b0 [2] a3 aa [2] bd b7 [2] bf b6 [2] a4 b0 [2] b8 b7 [2] a4 98 }

  condition:
    any of them
}