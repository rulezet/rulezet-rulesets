rule TTP_XOR_MULT_DOSStub_cfc2 {
  strings:
    $key_cfc2 = { 9b aa [2] ef b2 [2] a8 b0 [2] ef a1 [2] a1 ad [2] ad a7 [2] ba ac [2] a1 e2 [2] 9c }

  condition:
    any of them
}