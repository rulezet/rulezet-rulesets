rule TTP_XOR_MULT_DOSStub_2021 {
  strings:
    $key_2021 = { 74 49 [2] 00 51 [2] 47 53 [2] 00 42 [2] 4e 4e [2] 42 44 [2] 55 4f [2] 4e 01 [2] 73 }

  condition:
    any of them
}