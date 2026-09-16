rule TTP_XOR_QUAD_CurrentVersionRun_d29e {
  strings:
    $key_d29e = { 81 f1 [2] a5 ff [2] 8e d3 [2] a0 f1 [2] b4 ea [2] bb f0 [2] a5 ed [2] a7 ec [2] bc ea [2] a0 ed [2] bc c2 }

  condition:
    any of them
}