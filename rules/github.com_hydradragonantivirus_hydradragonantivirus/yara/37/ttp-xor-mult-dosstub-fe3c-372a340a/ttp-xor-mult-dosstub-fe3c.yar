rule TTP_XOR_MULT_DOSStub_fe3c {
  strings:
    $key_fe3c = { aa 54 [2] de 4c [2] 99 4e [2] de 5f [2] 90 53 [2] 9c 59 [2] 8b 52 [2] 90 1c [2] ad }

  condition:
    any of them
}