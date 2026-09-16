rule TTP_XOR_MULT_DOSStub_2030 {
  strings:
    $key_2030 = { 74 58 [2] 00 40 [2] 47 42 [2] 00 53 [2] 4e 5f [2] 42 55 [2] 55 5e [2] 4e 10 [2] 73 }

  condition:
    any of them
}