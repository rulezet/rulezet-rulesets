rule TTP_XOR_MULT_DOSStub_7e30 {
  strings:
    $key_7e30 = { 2a 58 [2] 5e 40 [2] 19 42 [2] 5e 53 [2] 10 5f [2] 1c 55 [2] 0b 5e [2] 10 10 [2] 2d }

  condition:
    any of them
}