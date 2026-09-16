rule TTP_XOR_MULT_DOSStub_fe10 {
  strings:
    $key_fe10 = { aa 78 [2] de 60 [2] 99 62 [2] de 73 [2] 90 7f [2] 9c 75 [2] 8b 7e [2] 90 30 [2] ad }

  condition:
    any of them
}