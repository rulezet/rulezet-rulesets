rule TTP_XOR_MULT_DOSStub_0b30 {
  strings:
    $key_0b30 = { 5f 58 [2] 2b 40 [2] 6c 42 [2] 2b 53 [2] 65 5f [2] 69 55 [2] 7e 5e [2] 65 10 [2] 58 }

  condition:
    any of them
}