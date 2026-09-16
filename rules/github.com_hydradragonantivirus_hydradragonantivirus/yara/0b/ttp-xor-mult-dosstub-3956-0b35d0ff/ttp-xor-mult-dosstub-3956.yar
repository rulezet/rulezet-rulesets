rule TTP_XOR_MULT_DOSStub_3956 {
  strings:
    $key_3956 = { 6d 3e [2] 19 26 [2] 5e 24 [2] 19 35 [2] 57 39 [2] 5b 33 [2] 4c 38 [2] 57 76 [2] 6a }

  condition:
    any of them
}