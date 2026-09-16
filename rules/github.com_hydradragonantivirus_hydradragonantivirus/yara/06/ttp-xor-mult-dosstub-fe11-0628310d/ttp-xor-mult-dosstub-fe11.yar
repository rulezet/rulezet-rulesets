rule TTP_XOR_MULT_DOSStub_fe11 {
  strings:
    $key_fe11 = { aa 79 [2] de 61 [2] 99 63 [2] de 72 [2] 90 7e [2] 9c 74 [2] 8b 7f [2] 90 31 [2] ad }

  condition:
    any of them
}