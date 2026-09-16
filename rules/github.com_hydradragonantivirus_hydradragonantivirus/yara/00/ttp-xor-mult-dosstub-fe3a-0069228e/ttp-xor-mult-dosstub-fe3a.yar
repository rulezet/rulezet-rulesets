rule TTP_XOR_MULT_DOSStub_fe3a {
  strings:
    $key_fe3a = { aa 52 [2] de 4a [2] 99 48 [2] de 59 [2] 90 55 [2] 9c 5f [2] 8b 54 [2] 90 1a [2] ad }

  condition:
    any of them
}