rule TTP_XOR_MULT_DOSStub_fe72 {
  strings:
    $key_fe72 = { aa 1a [2] de 02 [2] 99 00 [2] de 11 [2] 90 1d [2] 9c 17 [2] 8b 1c [2] 90 52 [2] ad }

  condition:
    any of them
}