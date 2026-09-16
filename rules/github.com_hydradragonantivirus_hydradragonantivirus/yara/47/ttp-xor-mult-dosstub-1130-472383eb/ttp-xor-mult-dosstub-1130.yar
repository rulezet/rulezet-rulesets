rule TTP_XOR_MULT_DOSStub_1130 {
  strings:
    $key_1130 = { 45 58 [2] 31 40 [2] 76 42 [2] 31 53 [2] 7f 5f [2] 73 55 [2] 64 5e [2] 7f 10 [2] 42 }

  condition:
    any of them
}