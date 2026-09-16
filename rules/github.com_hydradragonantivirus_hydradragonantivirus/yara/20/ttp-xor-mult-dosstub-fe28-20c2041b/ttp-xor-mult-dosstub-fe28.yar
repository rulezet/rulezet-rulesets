rule TTP_XOR_MULT_DOSStub_fe28 {
  strings:
    $key_fe28 = { aa 40 [2] de 58 [2] 99 5a [2] de 4b [2] 90 47 [2] 9c 4d [2] 8b 46 [2] 90 08 [2] ad }

  condition:
    any of them
}