rule TTP_XOR_MULT_DOSStub_fec2 {
  strings:
    $key_fec2 = { aa aa [2] de b2 [2] 99 b0 [2] de a1 [2] 90 ad [2] 9c a7 [2] 8b ac [2] 90 e2 [2] ad }

  condition:
    any of them
}