rule TTP_XOR_MULT_DOSStub_0930 {
  strings:
    $key_0930 = { 5d 58 [2] 29 40 [2] 6e 42 [2] 29 53 [2] 67 5f [2] 6b 55 [2] 7c 5e [2] 67 10 [2] 5a }

  condition:
    any of them
}