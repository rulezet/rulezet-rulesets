rule TTP_XOR_MULT_DOSStub_7e47 {
  strings:
    $key_7e47 = { 2a 2f [2] 5e 37 [2] 19 35 [2] 5e 24 [2] 10 28 [2] 1c 22 [2] 0b 29 [2] 10 67 [2] 2d }

  condition:
    any of them
}