rule TTP_XOR_MULT_DOSStub_0f41 {
  strings:
    $key_0f41 = { 5b 29 [2] 2f 31 [2] 68 33 [2] 2f 22 [2] 61 2e [2] 6d 24 [2] 7a 2f [2] 61 61 [2] 5c }

  condition:
    any of them
}