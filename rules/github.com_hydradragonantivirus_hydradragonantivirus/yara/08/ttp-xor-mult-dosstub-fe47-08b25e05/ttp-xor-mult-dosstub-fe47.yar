rule TTP_XOR_MULT_DOSStub_fe47 {
  strings:
    $key_fe47 = { aa 2f [2] de 37 [2] 99 35 [2] de 24 [2] 90 28 [2] 9c 22 [2] 8b 29 [2] 90 67 [2] ad }

  condition:
    any of them
}