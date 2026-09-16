rule TTP_XOR_MULT_DOSStub_5e17 {
  strings:
    $key_5e17 = { 0a 7f [2] 7e 67 [2] 39 65 [2] 7e 74 [2] 30 78 [2] 3c 72 [2] 2b 79 [2] 30 37 [2] 0d }

  condition:
    any of them
}