rule TTP_XOR_MULT_DOSStub_fe20 {
  strings:
    $key_fe20 = { aa 48 [2] de 50 [2] 99 52 [2] de 43 [2] 90 4f [2] 9c 45 [2] 8b 4e [2] 90 00 [2] ad }

  condition:
    any of them
}