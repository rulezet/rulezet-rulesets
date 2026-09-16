rule TTP_XOR_MULT_DOSStub_1956 {
  strings:
    $key_1956 = { 4d 3e [2] 39 26 [2] 7e 24 [2] 39 35 [2] 77 39 [2] 7b 33 [2] 6c 38 [2] 77 76 [2] 4a }

  condition:
    any of them
}