rule TTP_XOR_MULT_DOSStub_39f1 {
  strings:
    $key_39f1 = { 6d 99 [2] 19 81 [2] 5e 83 [2] 19 92 [2] 57 9e [2] 5b 94 [2] 4c 9f [2] 57 d1 [2] 6a }

  condition:
    any of them
}