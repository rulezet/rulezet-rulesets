rule TTP_XOR_MULT_DOSStub_1b17 {
  strings:
    $key_1b17 = { 4f 7f [2] 3b 67 [2] 7c 65 [2] 3b 74 [2] 75 78 [2] 79 72 [2] 6e 79 [2] 75 37 [2] 48 }

  condition:
    any of them
}