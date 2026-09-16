rule TTP_XOR_MULT_DOSStub_7e27 {
  strings:
    $key_7e27 = { 2a 4f [2] 5e 57 [2] 19 55 [2] 5e 44 [2] 10 48 [2] 1c 42 [2] 0b 49 [2] 10 07 [2] 2d }

  condition:
    any of them
}