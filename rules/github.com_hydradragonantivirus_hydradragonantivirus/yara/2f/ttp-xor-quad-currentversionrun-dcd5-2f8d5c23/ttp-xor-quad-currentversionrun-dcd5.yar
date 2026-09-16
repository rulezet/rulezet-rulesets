rule TTP_XOR_QUAD_CurrentVersionRun_dcd5 {
  strings:
    $key_dcd5 = { 8f ba [2] ab b4 [2] 80 98 [2] ae ba [2] ba a1 [2] b5 bb [2] ab a6 [2] a9 a7 [2] b2 a1 [2] ae a6 [2] b2 89 }

  condition:
    any of them
}