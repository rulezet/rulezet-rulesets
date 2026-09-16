rule TTP_XOR_MULT_DOSStub_7e20 {
  strings:
    $key_7e20 = { 2a 48 [2] 5e 50 [2] 19 52 [2] 5e 43 [2] 10 4f [2] 1c 45 [2] 0b 4e [2] 10 00 [2] 2d }

  condition:
    any of them
}