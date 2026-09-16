rule TTP_XOR_MULT_DOSStub_fe54 {
  strings:
    $key_fe54 = { aa 3c [2] de 24 [2] 99 26 [2] de 37 [2] 90 3b [2] 9c 31 [2] 8b 3a [2] 90 74 [2] ad }

  condition:
    any of them
}