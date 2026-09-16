rule TTP_XOR_MULT_DOSStub_fe4e {
  strings:
    $key_fe4e = { aa 26 [2] de 3e [2] 99 3c [2] de 2d [2] 90 21 [2] 9c 2b [2] 8b 20 [2] 90 6e [2] ad }

  condition:
    any of them
}