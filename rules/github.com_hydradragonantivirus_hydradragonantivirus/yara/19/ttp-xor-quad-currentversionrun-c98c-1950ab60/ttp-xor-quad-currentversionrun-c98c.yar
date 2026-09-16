rule TTP_XOR_QUAD_CurrentVersionRun_c98c {
  strings:
    $key_c98c = { 9a e3 [2] be ed [2] 95 c1 [2] bb e3 [2] af f8 [2] a0 e2 [2] be ff [2] bc fe [2] a7 f8 [2] bb ff [2] a7 d0 }

  condition:
    any of them
}