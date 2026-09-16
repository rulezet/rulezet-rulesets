rule TTP_XOR_QUAD_CurrentVersionRun_d5be {
  strings:
    $key_d5be = { 86 d1 [2] a2 df [2] 89 f3 [2] a7 d1 [2] b3 ca [2] bc d0 [2] a2 cd [2] a0 cc [2] bb ca [2] a7 cd [2] bb e2 }

  condition:
    any of them
}