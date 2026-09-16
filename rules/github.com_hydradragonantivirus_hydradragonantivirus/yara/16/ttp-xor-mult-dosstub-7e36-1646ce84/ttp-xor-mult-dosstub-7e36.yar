rule TTP_XOR_MULT_DOSStub_7e36 {
  strings:
    $key_7e36 = { 2a 5e [2] 5e 46 [2] 19 44 [2] 5e 55 [2] 10 59 [2] 1c 53 [2] 0b 58 [2] 10 16 [2] 2d }

  condition:
    any of them
}