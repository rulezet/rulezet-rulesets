rule TTP_XOR_QUAD_CurrentVersionRun_cbad {
  strings:
    $key_cbad = { 98 c2 [2] bc cc [2] 97 e0 [2] b9 c2 [2] ad d9 [2] a2 c3 [2] bc de [2] be df [2] a5 d9 [2] b9 de [2] a5 f1 }

  condition:
    any of them
}