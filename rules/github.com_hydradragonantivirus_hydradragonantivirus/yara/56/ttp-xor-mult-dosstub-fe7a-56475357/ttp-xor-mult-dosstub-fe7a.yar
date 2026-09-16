rule TTP_XOR_MULT_DOSStub_fe7a {
  strings:
    $key_fe7a = { aa 12 [2] de 0a [2] 99 08 [2] de 19 [2] 90 15 [2] 9c 1f [2] 8b 14 [2] 90 5a [2] ad }

  condition:
    any of them
}