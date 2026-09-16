rule TTP_XOR_MULT_DOSStub_fe57 {
  strings:
    $key_fe57 = { aa 3f [2] de 27 [2] 99 25 [2] de 34 [2] 90 38 [2] 9c 32 [2] 8b 39 [2] 90 77 [2] ad }

  condition:
    any of them
}