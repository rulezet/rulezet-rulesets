rule TTP_XOR_MULT_DOSStub_fe15 {
  strings:
    $key_fe15 = { aa 7d [2] de 65 [2] 99 67 [2] de 76 [2] 90 7a [2] 9c 70 [2] 8b 7b [2] 90 35 [2] ad }

  condition:
    any of them
}