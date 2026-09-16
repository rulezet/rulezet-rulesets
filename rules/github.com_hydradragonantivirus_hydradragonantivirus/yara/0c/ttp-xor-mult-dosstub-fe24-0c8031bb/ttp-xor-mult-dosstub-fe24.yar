rule TTP_XOR_MULT_DOSStub_fe24 {
  strings:
    $key_fe24 = { aa 4c [2] de 54 [2] 99 56 [2] de 47 [2] 90 4b [2] 9c 41 [2] 8b 4a [2] 90 04 [2] ad }

  condition:
    any of them
}