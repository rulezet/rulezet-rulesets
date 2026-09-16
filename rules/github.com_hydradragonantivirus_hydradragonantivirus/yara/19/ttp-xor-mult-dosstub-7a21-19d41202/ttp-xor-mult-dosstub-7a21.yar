rule TTP_XOR_MULT_DOSStub_7a21 {
  strings:
    $key_7a21 = { 2e 49 [2] 5a 51 [2] 1d 53 [2] 5a 42 [2] 14 4e [2] 18 44 [2] 0f 4f [2] 14 01 [2] 29 }

  condition:
    any of them
}