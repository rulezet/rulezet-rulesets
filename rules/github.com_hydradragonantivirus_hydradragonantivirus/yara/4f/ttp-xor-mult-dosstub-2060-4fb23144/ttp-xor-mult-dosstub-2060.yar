rule TTP_XOR_MULT_DOSStub_2060 {
  strings:
    $key_2060 = { 74 08 [2] 00 10 [2] 47 12 [2] 00 03 [2] 4e 0f [2] 42 05 [2] 55 0e [2] 4e 40 [2] 73 }

  condition:
    any of them
}