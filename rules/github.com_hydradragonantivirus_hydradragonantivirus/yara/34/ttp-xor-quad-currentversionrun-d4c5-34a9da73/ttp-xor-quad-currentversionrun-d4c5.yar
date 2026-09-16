rule TTP_XOR_QUAD_CurrentVersionRun_d4c5 {
  strings:
    $key_d4c5 = { 87 aa [2] a3 a4 [2] 88 88 [2] a6 aa [2] b2 b1 [2] bd ab [2] a3 b6 [2] a1 b7 [2] ba b1 [2] a6 b6 [2] ba 99 }

  condition:
    any of them
}