rule TTP_XOR_MULT_DOSStub_fe02 {
  strings:
    $key_fe02 = { aa 6a [2] de 72 [2] 99 70 [2] de 61 [2] 90 6d [2] 9c 67 [2] 8b 6c [2] 90 22 [2] ad }

  condition:
    any of them
}