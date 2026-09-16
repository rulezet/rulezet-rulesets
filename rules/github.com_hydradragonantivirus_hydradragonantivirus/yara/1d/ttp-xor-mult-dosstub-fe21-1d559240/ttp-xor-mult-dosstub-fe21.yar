rule TTP_XOR_MULT_DOSStub_fe21 {
  strings:
    $key_fe21 = { aa 49 [2] de 51 [2] 99 53 [2] de 42 [2] 90 4e [2] 9c 44 [2] 8b 4f [2] 90 01 [2] ad }

  condition:
    any of them
}