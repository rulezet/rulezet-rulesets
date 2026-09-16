rule TTP_XOR_MULT_DOSStub_3950 {
  strings:
    $key_3950 = { 6d 38 [2] 19 20 [2] 5e 22 [2] 19 33 [2] 57 3f [2] 5b 35 [2] 4c 3e [2] 57 70 [2] 6a }

  condition:
    any of them
}