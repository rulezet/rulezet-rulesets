rule TTP_XOR_MULT_DOSStub_0e17 {
  strings:
    $key_0e17 = { 5a 7f [2] 2e 67 [2] 69 65 [2] 2e 74 [2] 60 78 [2] 6c 72 [2] 7b 79 [2] 60 37 [2] 5d }

  condition:
    any of them
}