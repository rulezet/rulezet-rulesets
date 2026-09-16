rule TTP_XOR_MULT_DOSStub_fe74 {
  strings:
    $key_fe74 = { aa 1c [2] de 04 [2] 99 06 [2] de 17 [2] 90 1b [2] 9c 11 [2] 8b 1a [2] 90 54 [2] ad }

  condition:
    any of them
}