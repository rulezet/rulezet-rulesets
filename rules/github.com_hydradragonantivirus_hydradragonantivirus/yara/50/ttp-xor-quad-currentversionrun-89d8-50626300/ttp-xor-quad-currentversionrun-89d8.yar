rule TTP_XOR_QUAD_CurrentVersionRun_89d8 {
  strings:
    $key_89d8 = { da b7 [2] fe b9 [2] d5 95 [2] fb b7 [2] ef ac [2] e0 b6 [2] fe ab [2] fc aa [2] e7 ac [2] fb ab [2] e7 84 }

  condition:
    any of them
}