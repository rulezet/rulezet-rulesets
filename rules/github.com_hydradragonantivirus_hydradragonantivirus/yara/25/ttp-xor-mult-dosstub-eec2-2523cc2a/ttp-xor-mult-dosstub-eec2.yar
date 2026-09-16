rule TTP_XOR_MULT_DOSStub_eec2 {
  strings:
    $key_eec2 = { ba aa [2] ce b2 [2] 89 b0 [2] ce a1 [2] 80 ad [2] 8c a7 [2] 9b ac [2] 80 e2 [2] bd }

  condition:
    any of them
}