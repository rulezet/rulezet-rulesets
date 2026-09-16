rule TTP_XOR_MULT_DOSStub_fee7 {
  strings:
    $key_fee7 = { aa 8f [2] de 97 [2] 99 95 [2] de 84 [2] 90 88 [2] 9c 82 [2] 8b 89 [2] 90 c7 [2] ad }

  condition:
    any of them
}