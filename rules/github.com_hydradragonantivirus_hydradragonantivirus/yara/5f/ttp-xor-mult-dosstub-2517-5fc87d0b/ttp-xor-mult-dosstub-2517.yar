rule TTP_XOR_MULT_DOSStub_2517 {
  strings:
    $key_2517 = { 71 7f [2] 05 67 [2] 42 65 [2] 05 74 [2] 4b 78 [2] 47 72 [2] 50 79 [2] 4b 37 [2] 76 }

  condition:
    any of them
}