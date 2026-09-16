rule TTP_XOR_MULT_DOSStub_fe7f {
  strings:
    $key_fe7f = { aa 17 [2] de 0f [2] 99 0d [2] de 1c [2] 90 10 [2] 9c 1a [2] 8b 11 [2] 90 5f [2] ad }

  condition:
    any of them
}