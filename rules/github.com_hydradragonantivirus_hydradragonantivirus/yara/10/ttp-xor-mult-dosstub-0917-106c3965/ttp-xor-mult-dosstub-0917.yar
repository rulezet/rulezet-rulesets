rule TTP_XOR_MULT_DOSStub_0917 {
  strings:
    $key_0917 = { 5d 7f [2] 29 67 [2] 6e 65 [2] 29 74 [2] 67 78 [2] 6b 72 [2] 7c 79 [2] 67 37 [2] 5a }

  condition:
    any of them
}