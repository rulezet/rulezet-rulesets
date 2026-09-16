rule TTP_XOR_MULT_DOSStub_3946 {
  strings:
    $key_3946 = { 6d 2e [2] 19 36 [2] 5e 34 [2] 19 25 [2] 57 29 [2] 5b 23 [2] 4c 28 [2] 57 66 [2] 6a }

  condition:
    any of them
}