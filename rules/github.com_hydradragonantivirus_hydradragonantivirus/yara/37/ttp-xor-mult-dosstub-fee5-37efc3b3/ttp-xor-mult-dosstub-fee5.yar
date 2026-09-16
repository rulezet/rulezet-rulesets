rule TTP_XOR_MULT_DOSStub_fee5 {
  strings:
    $key_fee5 = { aa 8d [2] de 95 [2] 99 97 [2] de 86 [2] 90 8a [2] 9c 80 [2] 8b 8b [2] 90 c5 [2] ad }

  condition:
    any of them
}