rule TTP_XOR_MULT_DOSStub_3941 {
  strings:
    $key_3941 = { 6d 29 [2] 19 31 [2] 5e 33 [2] 19 22 [2] 57 2e [2] 5b 24 [2] 4c 2f [2] 57 61 [2] 6a }

  condition:
    any of them
}