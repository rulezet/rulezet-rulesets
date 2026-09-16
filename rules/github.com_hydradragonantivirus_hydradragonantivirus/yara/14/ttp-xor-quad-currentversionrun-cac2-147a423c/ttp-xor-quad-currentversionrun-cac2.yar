rule TTP_XOR_QUAD_CurrentVersionRun_cac2 {
  strings:
    $key_cac2 = { 99 ad [2] bd a3 [2] 96 8f [2] b8 ad [2] ac b6 [2] a3 ac [2] bd b1 [2] bf b0 [2] a4 b6 [2] b8 b1 [2] a4 9e }

  condition:
    any of them
}