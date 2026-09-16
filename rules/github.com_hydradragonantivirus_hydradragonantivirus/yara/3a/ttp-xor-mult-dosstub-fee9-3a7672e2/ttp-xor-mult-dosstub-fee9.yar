rule TTP_XOR_MULT_DOSStub_fee9 {
  strings:
    $key_fee9 = { aa 81 [2] de 99 [2] 99 9b [2] de 8a [2] 90 86 [2] 9c 8c [2] 8b 87 [2] 90 c9 [2] ad }

  condition:
    any of them
}