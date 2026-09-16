rule TTP_XOR_MULT_DOSStub_fe16 {
  strings:
    $key_fe16 = { aa 7e [2] de 66 [2] 99 64 [2] de 75 [2] 90 79 [2] 9c 73 [2] 8b 78 [2] 90 36 [2] ad }

  condition:
    any of them
}