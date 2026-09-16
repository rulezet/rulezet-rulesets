rule TTP_XOR_MULT_DOSStub_542c {
  strings:
    $key_542c = { 00 44 [2] 74 5c [2] 33 5e [2] 74 4f [2] 3a 43 [2] 36 49 [2] 21 42 [2] 3a 0c [2] 07 }

  condition:
    any of them
}