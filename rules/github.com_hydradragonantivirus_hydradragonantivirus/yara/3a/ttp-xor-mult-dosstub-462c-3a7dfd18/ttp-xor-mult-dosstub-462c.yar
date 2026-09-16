rule TTP_XOR_MULT_DOSStub_462c {
  strings:
    $key_462c = { 12 44 [2] 66 5c [2] 21 5e [2] 66 4f [2] 28 43 [2] 24 49 [2] 33 42 [2] 28 0c [2] 15 }

  condition:
    any of them
}