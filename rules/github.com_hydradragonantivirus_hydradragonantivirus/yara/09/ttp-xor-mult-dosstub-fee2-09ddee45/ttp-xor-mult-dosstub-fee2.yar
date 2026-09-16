rule TTP_XOR_MULT_DOSStub_fee2 {
  strings:
    $key_fee2 = { aa 8a [2] de 92 [2] 99 90 [2] de 81 [2] 90 8d [2] 9c 87 [2] 8b 8c [2] 90 c2 [2] ad }

  condition:
    any of them
}