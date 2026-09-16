rule TTP_XOR_MULT_DOSStub_152c {
  strings:
    $key_152c = { 41 44 [2] 35 5c [2] 72 5e [2] 35 4f [2] 7b 43 [2] 77 49 [2] 60 42 [2] 7b 0c [2] 46 }

  condition:
    any of them
}