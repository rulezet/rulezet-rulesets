rule TTP_XOR_MULT_DOSStub_fe69 {
  strings:
    $key_fe69 = { aa 01 [2] de 19 [2] 99 1b [2] de 0a [2] 90 06 [2] 9c 0c [2] 8b 07 [2] 90 49 [2] ad }

  condition:
    any of them
}