rule TTP_XOR_MULT_DOSStub_fe56 {
  strings:
    $key_fe56 = { aa 3e [2] de 26 [2] 99 24 [2] de 35 [2] 90 39 [2] 9c 33 [2] 8b 38 [2] 90 76 [2] ad }

  condition:
    any of them
}