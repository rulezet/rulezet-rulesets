rule TTP_XOR_MULT_DOSStub_fee6 {
  strings:
    $key_fee6 = { aa 8e [2] de 96 [2] 99 94 [2] de 85 [2] 90 89 [2] 9c 83 [2] 8b 88 [2] 90 c6 [2] ad }

  condition:
    any of them
}