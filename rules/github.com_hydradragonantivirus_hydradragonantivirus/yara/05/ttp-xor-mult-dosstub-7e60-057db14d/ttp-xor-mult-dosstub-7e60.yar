rule TTP_XOR_MULT_DOSStub_7e60 {
  strings:
    $key_7e60 = { 2a 08 [2] 5e 10 [2] 19 12 [2] 5e 03 [2] 10 0f [2] 1c 05 [2] 0b 0e [2] 10 40 [2] 2d }

  condition:
    any of them
}