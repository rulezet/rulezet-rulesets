rule TTP_XOR_MULT_DOSStub_fe4a {
  strings:
    $key_fe4a = { aa 22 [2] de 3a [2] 99 38 [2] de 29 [2] 90 25 [2] 9c 2f [2] 8b 24 [2] 90 6a [2] ad }

  condition:
    any of them
}