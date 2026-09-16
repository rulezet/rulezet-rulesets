rule TTP_XOR_MULT_DOSStub_fee0 {
  strings:
    $key_fee0 = { aa 88 [2] de 90 [2] 99 92 [2] de 83 [2] 90 8f [2] 9c 85 [2] 8b 8e [2] 90 c0 [2] ad }

  condition:
    any of them
}