rule TTP_XOR_MULT_DOSStub_6530 {
  strings:
    $key_6530 = { 31 58 [2] 45 40 [2] 02 42 [2] 45 53 [2] 0b 5f [2] 07 55 [2] 10 5e [2] 0b 10 [2] 36 }

  condition:
    any of them
}