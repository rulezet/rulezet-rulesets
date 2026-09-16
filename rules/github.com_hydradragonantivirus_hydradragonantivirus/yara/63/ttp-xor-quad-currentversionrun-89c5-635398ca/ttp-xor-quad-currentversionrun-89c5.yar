rule TTP_XOR_QUAD_CurrentVersionRun_89c5 {
  strings:
    $key_89c5 = { da aa [2] fe a4 [2] d5 88 [2] fb aa [2] ef b1 [2] e0 ab [2] fe b6 [2] fc b7 [2] e7 b1 [2] fb b6 [2] e7 99 }

  condition:
    any of them
}