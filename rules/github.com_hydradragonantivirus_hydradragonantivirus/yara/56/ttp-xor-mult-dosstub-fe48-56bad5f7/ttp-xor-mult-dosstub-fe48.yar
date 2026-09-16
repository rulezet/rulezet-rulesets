rule TTP_XOR_MULT_DOSStub_fe48 {
  strings:
    $key_fe48 = { aa 20 [2] de 38 [2] 99 3a [2] de 2b [2] 90 27 [2] 9c 2d [2] 8b 26 [2] 90 68 [2] ad }

  condition:
    any of them
}