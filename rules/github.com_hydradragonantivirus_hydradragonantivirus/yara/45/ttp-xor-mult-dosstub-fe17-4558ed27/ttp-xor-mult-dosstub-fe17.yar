rule TTP_XOR_MULT_DOSStub_fe17 {
  strings:
    $key_fe17 = { aa 7f [2] de 67 [2] 99 65 [2] de 74 [2] 90 78 [2] 9c 72 [2] 8b 79 [2] 90 37 [2] ad }

  condition:
    any of them
}