rule TTP_XOR_MULT_DOSStub_fe51 {
  strings:
    $key_fe51 = { aa 39 [2] de 21 [2] 99 23 [2] de 32 [2] 90 3e [2] 9c 34 [2] 8b 3f [2] 90 71 [2] ad }

  condition:
    any of them
}