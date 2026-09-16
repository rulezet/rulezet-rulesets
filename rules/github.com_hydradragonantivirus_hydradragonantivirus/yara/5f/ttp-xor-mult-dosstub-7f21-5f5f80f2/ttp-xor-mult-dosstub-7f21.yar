rule TTP_XOR_MULT_DOSStub_7f21 {
  strings:
    $key_7f21 = { 2b 49 [2] 5f 51 [2] 18 53 [2] 5f 42 [2] 11 4e [2] 1d 44 [2] 0a 4f [2] 11 01 [2] 2c }

  condition:
    any of them
}