rule TTP_XOR_MULT_DOSStub_7e21 {
  strings:
    $key_7e21 = { 2a 49 [2] 5e 51 [2] 19 53 [2] 5e 42 [2] 10 4e [2] 1c 44 [2] 0b 4f [2] 10 01 [2] 2d }

  condition:
    any of them
}