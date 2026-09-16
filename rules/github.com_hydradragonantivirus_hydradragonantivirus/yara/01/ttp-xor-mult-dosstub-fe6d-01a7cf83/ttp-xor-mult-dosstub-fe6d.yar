rule TTP_XOR_MULT_DOSStub_fe6d {
  strings:
    $key_fe6d = { aa 05 [2] de 1d [2] 99 1f [2] de 0e [2] 90 02 [2] 9c 08 [2] 8b 03 [2] 90 4d [2] ad }

  condition:
    any of them
}