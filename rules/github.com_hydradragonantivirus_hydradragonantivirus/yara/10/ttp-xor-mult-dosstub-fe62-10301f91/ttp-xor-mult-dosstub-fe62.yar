rule TTP_XOR_MULT_DOSStub_fe62 {
  strings:
    $key_fe62 = { aa 0a [2] de 12 [2] 99 10 [2] de 01 [2] 90 0d [2] 9c 07 [2] 8b 0c [2] 90 42 [2] ad }

  condition:
    any of them
}