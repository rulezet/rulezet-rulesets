rule TTP_XOR_MULT_DOSStub_fe5c {
  strings:
    $key_fe5c = { aa 34 [2] de 2c [2] 99 2e [2] de 3f [2] 90 33 [2] 9c 39 [2] 8b 32 [2] 90 7c [2] ad }

  condition:
    any of them
}