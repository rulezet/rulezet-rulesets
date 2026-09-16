rule TTP_XOR_MULT_DOSStub_3917 {
  strings:
    $key_3917 = { 6d 7f [2] 19 67 [2] 5e 65 [2] 19 74 [2] 57 78 [2] 5b 72 [2] 4c 79 [2] 57 37 [2] 6a }

  condition:
    any of them
}