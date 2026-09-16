rule TTP_XOR_MULT_DOSStub_472c {
  strings:
    $key_472c = { 13 44 [2] 67 5c [2] 20 5e [2] 67 4f [2] 29 43 [2] 25 49 [2] 32 42 [2] 29 0c [2] 14 }

  condition:
    any of them
}