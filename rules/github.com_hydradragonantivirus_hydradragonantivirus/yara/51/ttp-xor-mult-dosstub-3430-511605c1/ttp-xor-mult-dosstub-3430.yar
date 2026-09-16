rule TTP_XOR_MULT_DOSStub_3430 {
  strings:
    $key_3430 = { 60 58 [2] 14 40 [2] 53 42 [2] 14 53 [2] 5a 5f [2] 56 55 [2] 41 5e [2] 5a 10 [2] 67 }

  condition:
    any of them
}