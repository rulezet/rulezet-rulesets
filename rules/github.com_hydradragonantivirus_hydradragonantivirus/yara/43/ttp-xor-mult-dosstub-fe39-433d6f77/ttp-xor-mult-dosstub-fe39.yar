rule TTP_XOR_MULT_DOSStub_fe39 {
  strings:
    $key_fe39 = { aa 51 [2] de 49 [2] 99 4b [2] de 5a [2] 90 56 [2] 9c 5c [2] 8b 57 [2] 90 19 [2] ad }

  condition:
    any of them
}