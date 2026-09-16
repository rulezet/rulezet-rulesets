rule TTP_XOR_MULT_DOSStub_2036 {
  strings:
    $key_2036 = { 74 5e [2] 00 46 [2] 47 44 [2] 00 55 [2] 4e 59 [2] 42 53 [2] 55 58 [2] 4e 16 [2] 73 }

  condition:
    any of them
}