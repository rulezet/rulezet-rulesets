rule TTP_XOR_MULT_DOSStub_7e11 {
  strings:
    $key_7e11 = { 2a 79 [2] 5e 61 [2] 19 63 [2] 5e 72 [2] 10 7e [2] 1c 74 [2] 0b 7f [2] 10 31 [2] 2d }

  condition:
    any of them
}