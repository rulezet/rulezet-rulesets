rule TTP_XOR_QUAD_CurrentVersionRun_89c4 {
  strings:
    $key_89c4 = { da ab [2] fe a5 [2] d5 89 [2] fb ab [2] ef b0 [2] e0 aa [2] fe b7 [2] fc b6 [2] e7 b0 [2] fb b7 [2] e7 98 }

  condition:
    any of them
}